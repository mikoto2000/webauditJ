package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BundleIntegrationTest {
  @TempDir Path dir;

  @Test
  void preservesRotatedGzipOutOfOrderEvidenceAndSharedCounts() throws Exception {
    var inputs = List.of(dir.resolve("access.log.1.gz"), dir.resolve("access.log"));
    for (int part = 0; part < 2; part++) {
      var text = new StringBuilder();
      for (int i = 0; i < 350; i++)
        text.append(
                BundleTest.LINE
                    .replace(
                        "00:00:00",
                        String.format(Locale.ROOT, "00:00:%02d", (699 - part * 350 - i) % 60))
                    .replace("404 0", "200 42"))
            .append('\n');
      if (part == 0) {
        try (var gz = new GZIPOutputStream(Files.newOutputStream(inputs.get(part)))) {
          gz.write(text.toString().getBytes(StandardCharsets.UTF_8));
        }
      } else Files.writeString(inputs.get(part), text);
    }
    Path target = dir.resolve("report");
    var report = Bundle.generate(inputs, target, new Options(), new BundleOptions());
    var rows = BundleRequestsTest.csv(target.resolve("suspicious-requests.csv"));
    assertEquals(700, rows.size());
    assertEquals(700, Json.number(Json.obj(report.get("summary")).get("total_requests")));
    assertEquals(700, Json.number(Json.obj(report.get("summary")).get("suspicious_requests")));
    var ids = new HashSet<String>();
    var files = new HashSet<String>();
    for (var row : rows) {
      assertTrue(ids.add(row.get("request_id")));
      files.add(row.get("source_file_id"));
    }
    assertEquals(2, files.size());
    var rate = BundleCoverageTest.index(report).get("ASPECT-rate");
    assertEquals(700, Json.number(rate.get("related_requests")));
    assertTrue(Json.number(rate.get("detections")) > 0);
    assertEquals(
        Json.MAPPER.writeValueAsString(report.get("summary")),
        Json.MAPPER.writeValueAsString(
            Json.object(Files.readString(target.resolve("report.json"))).get("summary")));
    for (var finding : Json.rows(Json.obj(report.get("analysis")).get("findings")))
      assertNotEquals("confirmed_success", Json.obj(finding.get("outcome")).get("verdict"));
  }

  @Test
  void escapesHostileEvidenceInHTMLCSVAndStructuredJSON() throws Exception {
    Path input = dir.resolve("hostile.log");
    String raw =
        BundleTest.LINE
                .replace("/.env", "/.env?x=</pre><script>alert(1)</script>")
                .replace("Browser", "=1+2")
            + "\n";
    Files.writeString(input, raw);
    Path target = dir.resolve("report");
    Bundle.generate(List.of(input), target, new Options(), new BundleOptions());
    var rows = BundleRequestsTest.csv(target.resolve("suspicious-requests.csv"));
    assertEquals(1, rows.size());
    assertEquals("'=1+2", rows.getFirst().get("user_agent"));
    for (var row : BundleRequestsTest.csv(target.resolve("findings.csv")))
      assertNotNull(Json.object(row.get("details_json")));
    String html = Files.readString(target.resolve("report.html"));
    assertFalse(html.contains("<script>"));
    assertTrue(html.contains("&lt;script&gt;"));
    assertEquals(raw, Files.readString(input));
  }

  @Test
  void disclosesWhetherTheBuildArtifactCanBeFingerprinted() throws Exception {
    Path input = dir.resolve("build.log");
    Files.writeString(input, BundleTest.LINE + "\n");
    Path target = dir.resolve("report");
    Bundle.generate(List.of(input), target, new Options(), new BundleOptions());
    var manifest = Json.object(Files.readString(target.resolve("manifest.json")));
    var build = Json.obj(manifest.get("build"));
    assertTrue(build.containsKey("artifact_sha256"));
    assertEquals("classes_directory_unhashed", build.get("artifact_hash_scope"));
    assertNull(build.get("artifact_sha256"));
  }
}
