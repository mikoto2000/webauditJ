package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.apache.commons.csv.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BundleRequestsTest {
  @TempDir Path dir;

  @Test
  void preservesNativeHourMembershipBeforeUnixEpoch() {
    Event e =
        LogParser.parse(
            BundleTest.LINE.replace("01/Nov/2026:00:00:00", "31/Dec/1969:23:59:59"),
            "access.log",
            1,
            "");
    var row =
        BundleRequests.baseDetection(
            "DET-hour",
            "webaudit",
            "WS-hour",
            "related",
            "WS-hour",
            "medium",
            "hour",
            Times.text(e.time),
            Times.text(e.time),
            e.ip,
            e.host,
            Json.map("count_quality", "exact"));
    var group =
        new BundleRequests.Group(
            row, new Signal(Map.of("id", "WS-hour"), e, 1, "hour", e.time, e.time), null, "");
    var snapshot =
        Json.map(
            "event",
            e.toMap(),
            "_time",
            Times.text(e.time),
            "hits",
            List.of(),
            "source_detections",
            List.of());
    assertEquals(
        1,
        BundleRequests.match(snapshot, e, new BundleRequests.Index(List.of(group)))
            .related()
            .size());
  }

  @Test
  void associatesEndOfAnalysisStatisticalSignals() throws Exception {
    Path input = dir.resolve("late.log");
    var text = new StringBuilder();
    for (int ip = 1; ip <= 21; ip++)
      for (int i = 0; i < (ip == 21 ? 200 : 1); i++)
        text.append(
                BundleTest.LINE
                    .replace("192.0.2.1", "192.0.2." + ip)
                    .replace("/.env", "/healthy")
                    .replace("404 0", "200 0"))
            .append('\n');
    Files.writeString(input, text);
    Path target = dir.resolve("late-report");
    var report = Bundle.generate(List.of(input), target, new Options(), new BundleOptions());
    assertTrue(Json.bool(report.get("evidence_complete")));
    assertTrue(
        csv(target.resolve("related-requests.csv")).stream()
            .anyMatch(row ->
                row.get("source_ip").equals("192.0.2.21")
                    && row.get("rule_ids").contains("WS-ip")));
  }

  @Test
  void excludesDistinctDuplicatesAndSuppressedHubCandidates() throws Exception {
    var rule =
        SourceMatcher.RULES.stream()
            .filter(r -> r.get("name").equals("crowdsecurity/http-probing"))
            .findFirst()
            .orElseThrow();
    var original = new LinkedHashMap<>(rule);
    try {
      rule.put("capacity", 2L);
      rule.put("leakspeed", "1m");
      rule.put("blackhole", "1m");
      rule.put("distinct", "evt.Meta.http_path");
      Path input = dir.resolve("hub.log");
      var text = new StringBuilder();
      for (String uri : List.of("/a", "/a", "/b", "/c", "/d", "/e", "/f"))
        text.append(BundleTest.LINE.replace("/.env", uri)).append('\n');
      Files.writeString(input, text);
      Path target = dir.resolve("hub-report");
      Bundle.generate(List.of(input), target, new Options(), new BundleOptions());
      var lines =
          csv(target.resolve("suspicious-requests.csv")).stream()
              .filter(row -> row.get("rule_ids").contains("crowdsecurity/http-probing"))
              .map(row -> row.get("source_line"))
              .toList();
      assertEquals(List.of("1", "3", "4"), lines);
    } finally {
      rule.clear();
      rule.putAll(original);
    }
  }

  static List<Map<String, String>> csv(Path path) throws IOException {
    try (var reader = Files.newBufferedReader(path);
        var parser =
            CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).get().parse(reader)) {
      var rows = new ArrayList<Map<String, String>>();
      for (var row : parser) rows.add(row.toMap());
      return rows;
    }
  }

  Path mixed() throws IOException {
    Path input = dir.resolve("access.log");
    var text = new StringBuilder();
    for (int i = 0; i < 25; i++)
      text.append(BundleTest.LINE.replace("/.env", "/.env?x=<script>")).append('\n');
    for (int i = 0; i < 600; i++)
      text.append(BundleTest.LINE.replace("/.env", "/healthy").replace("404 0", "200 0"))
          .append('\n');
    Files.writeString(input, text);
    return input;
  }

  @Test
  void preservesFullDistinctObservationsAndSeparatesRelated() throws Exception {
    Path target = dir.resolve("report");
    var report = Bundle.generate(List.of(mixed()), target, new Options(), new BundleOptions());
    var suspicious = csv(target.resolve("suspicious-requests.csv"));
    var related = csv(target.resolve("related-requests.csv"));
    var detections = csv(target.resolve("detections.csv"));
    assertEquals(25, suspicious.size());
    var ids = new HashSet<String>();
    for (var row : suspicious) {
      assertTrue(ids.add(row.get("request_id")));
      assertFalse(row.get("source_file_id").isEmpty());
      assertFalse(row.get("source_line").isEmpty());
      assertFalse(row.get("finding_ids").isEmpty());
      assertFalse(row.get("detection_ids").isEmpty());
      assertFalse(row.containsKey("outcome"));
    }
    assertTrue(related.size() >= 600);
    assertTrue(related.stream().anyMatch(row -> row.get("request_uri").equals("/healthy")));
    assertTrue(detections.size() > 25);
    assertTrue(Json.bool(report.get("evidence_complete")));
    var evidence = Json.obj(report.get("evidence"));
    assertEquals(suspicious.size(), Json.number(evidence.get("suspicious_requests")));
    assertEquals(related.size(), Json.number(evidence.get("related_requests")));
    try (var files = Files.list(target)) {
      assertTrue(files.noneMatch(path -> path.getFileName().toString().startsWith(".requests-")));
    }
  }

  @Test
  void disclosesSpoolTruncationAndKeepsFullAnalysisCounts() throws Exception {
    Path target = dir.resolve("limited");
    var options = new BundleOptions();
    options.maxSpoolBytes = 1;
    var report = Bundle.generate(List.of(mixed()), target, new Options(), options);
    assertEquals(625, Json.number(Json.obj(report.get("analysis")).get("requests")));
    assertFalse(Json.bool(report.get("evidence_complete")));
    assertFalse(Json.bool(report.get("complete")));
    assertEquals("partial", report.get("status"));
    assertTrue(csv(target.resolve("suspicious-requests.csv")).isEmpty());
    try (var files = Files.list(target)) {
      assertTrue(files.noneMatch(path -> path.getFileName().toString().startsWith(".requests-")));
    }
  }
}
