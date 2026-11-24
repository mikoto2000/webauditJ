package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class UpstreamEvidenceTest {
  @TempDir Path dir;

  @Test
  void hubAndAuraSignaturesRetainActualMatchingSourceLines() {
    boolean hub = false, aura = false;
    for (var row : Json.rows(Json.resource("upstream-golden.json"))) {
      var u = new Upstream(new Options(), new UpstreamEvidence(33554432));
      var lines = (List<?>) row.get("lines");
      for (int i = 0; i < lines.size(); i++) {
        try {
          u.observe(LogParser.parse(lines.get(i).toString(), "fixture.log", i + 1, ""));
        } catch (IllegalArgumentException ignored) {
        }
      }
      var alerts = new ArrayList<>(u.alerts);
      alerts.addAll(u.auraMatches());
      for (var alert : alerts) {
        var samples = Json.rows(alert.get("evidence"));
        assertFalse(samples.isEmpty(), alert.toString());
        assertTrue(samples.size() <= 8);
        for (var sample : samples) {
          int line = (int) Json.number(sample.get("line"));
          assertEquals("fixture.log", sample.get("file"));
          assertEquals(Core.clip(lines.get(line - 1).toString(), 4096), sample.get("raw"));
        }
      }
      hub |= !u.alerts.isEmpty();
      aura |= !u.auraMatches().isEmpty();
    }
    assertTrue(hub && aura);
  }

  @Test
  void auraAggregateSamplesBelongToTheSpecificAggregation() {
    var a = new AuraAnalysis(new Options(), new UpstreamEvidence(33554432));
    for (int i = 0; i < 50; i++) {
      a.observe(CorrelatorTest.event(i, 404));
      if (i < 20) a.observe(CorrelatorTest.event(i, 403));
    }
    var rare = CorrelatorTest.event(51, 200);
    rare.ua = "RareBrowser";
    rare.recordedUA = "RareBrowser";
    rare.raw = rare.raw.replace("Browser", "RareBrowser");
    a.observe(rare);
    var alerts = a.finish();
    assertEquals(3, alerts.size());
    for (var alert : alerts) {
      var samples = Json.rows(alert.get("evidence"));
      String rule = alert.get("rule_id").toString();
      assertEquals(rule.equals("rare_user_agent") ? 1 : 8, samples.size());
      for (var sample : samples) {
        String raw = sample.get("raw").toString();
        assertTrue(
            raw.contains(
                switch (rule) {
                  case "enumeration_404" -> " 404 ";
                  case "brute_force" -> " 403 ";
                  default -> "RareBrowser";
                }));
      }
      assertEquals(!rule.equals("rare_user_agent"), Json.bool(alert.get("evidence_truncated")));
    }
  }

  @Test
  void byteLimitsTruncationAndMissingSamplesAreExplicit() throws Exception {
    var samples = new ArrayList<Map<String, Object>>();
    var event = CorrelatorTest.event(0, 404);
    event.raw = "あ".repeat(2000);
    var budget = new UpstreamEvidence(4200);
    budget.add(samples, event);
    budget.add(samples, event);
    assertEquals(1, samples.size());
    assertTrue(Core.size(samples.getFirst().get("raw").toString()) <= 4096);
    assertTrue(Json.bool(samples.getFirst().get("evidence_truncated")));
    var alert = Json.map("count", 2);
    budget.attach(alert, samples);
    assertTrue(Json.bool(alert.get("evidence_truncated")));
    samples.clear();
    new UpstreamEvidence(0).add(samples, event);
    assertTrue(samples.isEmpty());
  }

  @Test
  void cliHtmlIncludesEscapedLogsFromGzipWithoutRereadingSources() throws Exception {
    Path input = dir.resolve("sample.log.gz"), output = dir.resolve("sample.html");
    String raw = CorrelatorTest.event(0, 404).raw.replace("/.env", "/.env?q=<script>bad</script>");
    try (var gzip = new GZIPOutputStream(Files.newOutputStream(input))) {
      gzip.write(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
    for (boolean toFile : List.of(false, true)) {
      var out = new StringWriter();
      var args = new ArrayList<>(List.of(input.toString()));
      if (toFile) args.addAll(List.of("-o", output.toString()));
      else args.addAll(List.of("--format", "html"));
      assertEquals(
          0,
          Main.run(
              args.toArray(String[]::new),
              out,
              new StringWriter(),
              Map.of("XDG_DATA_HOME", dir.toString()),
              null,
              null));
      String html = toFile ? Files.readString(output) : out.toString();
      int at = html.indexOf("<article id=\"upstream-");
      assertTrue(at > 0);
      String details = html.substring(at);
      assertTrue(details.contains("<pre>192.0.2.1"));
      assertTrue(details.contains("&lt;script&gt;bad&lt;/script&gt;"));
      assertFalse(details.contains("<script>"));
    }
    var options = new Options();
    options.retainUpstreamEvidence = true;
    options.maxEvidenceBytes = 0;
    var report = Engine.analyze(List.of(input), options);
    Files.delete(input);
    var out = new StringWriter();
    Reports.write(out, report, "html", "en");
    assertTrue(out.toString().contains("No retained source-log samples."));
    assertTrue(out.toString().contains("Evidence references truncated"));
  }
}
