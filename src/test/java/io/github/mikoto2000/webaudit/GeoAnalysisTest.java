package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class GeoAnalysisTest {
  @TempDir Path dir;

  @Test
  void enrichesAndCorrelatesWithoutChangingDetection() throws Exception {
    Path p = dir.resolve("a.log");
    Files.writeString(
        p,
        "8.8.8.8 - - [01/Nov/2026:00:00:00 +0000] \"GET /.env HTTP/1.1\" 404 0\n"
            + "8.8.8.9 - - [01/Nov/2026:00:00:01 +0000] \"GET /.env HTTP/1.1\" 404 0\n");
    var o = new Options();
    var plain = Engine.analyze(List.of(p), o);
    try (var g = GeoIP.open(GeoIPTest.db("country"), GeoIPTest.db("asn"), null, 4)) {
      o.geoIP = g;
      var rich = Engine.analyze(List.of(p), o);
      assertNotNull(rich.get("geoip"));
      var geo = Json.obj(rich.get("geoip"));
      var asn = Json.rows(geo.get("asns")).getFirst();
      assertEquals(2, Json.number(asn.get("ip_count")));
      assertTrue(Json.bool(asn.get("multiple_suspicious_ips")));
      assertEquals(1, Json.rows(geo.get("correlations")).size());
      for (var f : Json.rows(rich.get("findings"))) f.remove("geoip");
      UpstreamTest.equalJson(plain.get("findings"), rich.get("findings"));
    }
  }

  @Test
  void reportsPeerLimitAndCountsBeyondDisplaySamples() throws Exception {
    Path p = dir.resolve("a.log");
    var text = new StringBuilder();
    for (int i = 1; i <= 70; i++)
      text.append("8.8.8.")
          .append(i)
          .append(" - - [01/Nov/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1\n");
    Files.writeString(p, text);
    var o = new Options();
    try (var g = GeoIP.open(GeoIPTest.db("country"), GeoIPTest.db("asn"), null, 100)) {
      o.geoIP = g;
      var r = Engine.analyze(List.of(p), o);
      assertNotNull(r.get("geoip"));
      var asn = Json.rows(Json.obj(r.get("geoip")).get("asns")).getFirst();
      assertEquals(70, Json.number(asn.get("ip_count")));
      assertEquals(64, ((List<?>) asn.get("ips")).size());
    }
    o.maxKeys = 2;
    try (var g = GeoIP.open(GeoIPTest.db("country"), GeoIPTest.db("asn"), null, 2)) {
      o.geoIP = g;
      var r = Engine.analyze(List.of(p), o);
      assertTrue(Json.bool(r.get("partial")));
      assertTrue(Json.bool(Json.obj(r.get("geoip")).get("truncated")));
      assertEquals(2, Json.number(g.metrics().get("cached_ips")));
    }
  }
}
