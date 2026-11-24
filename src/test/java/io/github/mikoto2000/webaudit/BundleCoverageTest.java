package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BundleCoverageTest {
  @TempDir Path dir;

  @Test
  void doesNotClaimASNSimilarityWasEvaluatedWithOnlyCountryDatabase() throws Exception {
    Path input = dir.resolve("country-only.log");
    Files.writeString(input, BundleTest.LINE.replace("192.0.2.1", "8.8.8.8") + "\n");
    try (var geo = GeoIP.open(GeoIPTest.db("country"), "", null, 10)) {
      var options = new Options();
      options.geoIP = geo;
      var report =
          Bundle.generate(List.of(input), dir.resolve("report"), options, new BundleOptions());
      assertEquals("unable", index(report).get("RULE-geoip-geoip-similarity").get("status"));
    }
  }

  static Map<String, Map<String, Object>> index(Map<String, Object> report) {
    var out = new HashMap<String, Map<String, Object>>();
    for (var row : Json.rows(report.get("coverage"))) out.put((String) row.get("id"), row);
    return out;
  }

  @Test
  void separatesPartialHitUnsupportedUnableAndEveryRule() throws Exception {
    Path input = dir.resolve("access.log");
    Files.writeString(input, BundleTest.LINE.replace(" \"-\" \"Browser\"", "") + "\nbad record\n");
    var report =
        Bundle.generate(List.of(input), dir.resolve("report"), new Options(), new BundleOptions());
    var rows = index(report);
    var hit = rows.get("ASPECT-sensitive_file");
    assertTrue(Json.bool(hit.get("has_detections")));
    assertFalse(Json.bool(hit.get("complete")));
    assertEquals("partial", hit.get("status"));
    assertEquals(1, Json.number(hit.get("detected_requests")));
    assertEquals("unsupported", rows.get("ASPECT-ip_reputation").get("status"));
    assertEquals("unsupported", rows.get("ASPECT-request_body").get("status"));
    assertEquals("partial", rows.get("RULE-webaudit-WA-method").get("status"));
    assertEquals("unable", rows.get("RULE-webaudit-WA-scanner").get("status"));
    assertEquals("not_performed", rows.get("ASPECT-multi_ip").get("status"));
    for (var rule : Json.rows(Json.resource("rules.json")))
      assertNotNull(rows.get("RULE-webaudit-" + rule.get("id")));
    for (var rule : SourceMatcher.RULES) assertNotNull(rows.get("RULE-hub-" + rule.get("name")));
    assertTrue(Files.exists(dir.resolve("report/analysis-rules.csv")));
    assertTrue(Files.exists(dir.resolve("report/analysis-coverage.csv")));
  }

  @Test
  void preservesNoHitAndInsufficientBaseline() throws Exception {
    Path input = dir.resolve("normal.log");
    Files.writeString(input, BundleTest.LINE.replace("/.env", "/healthy") + "\n");
    var report =
        Bundle.generate(List.of(input), dir.resolve("report"), new Options(), new BundleOptions());
    var rows = index(report);
    assertEquals("no_detection", rows.get("RULE-webaudit-WA-sqli").get("status"));
    assertTrue(Json.bool(rows.get("RULE-webaudit-WA-sqli").get("complete")));
    assertEquals("unable", rows.get("RULE-webaudit-WS-ip").get("status"));
  }

  @Test
  void keepsAspectRequestUnionSeparateFromRuleHits() throws Exception {
    Path input = dir.resolve("mixed.log");
    Files.writeString(
        input,
        BundleTest.LINE.replace("/.env", "/?cmd=;whoami;&serialized=java.lang.Runtime") + "\n");
    var report =
        Bundle.generate(List.of(input), dir.resolve("report"), new Options(), new BundleOptions());
    var row = index(report).get("ASPECT-rce");
    assertEquals(1, Json.number(row.get("detected_requests")));
    assertTrue(Json.number(row.get("detections")) >= 2);
    assertEquals("partial", row.get("status"));
  }
}
