package io.github.mikoto2000.webaudit;

import java.io.*;
import java.nio.file.*;
import java.util.*;

final class ManagedGeoIP {
  record Opened(GeoIP geo, List<String> warnings) {}

  static Opened open(String country, String asn, Path dir, Path legacy, int capacity)
      throws IOException {
    if (dir == null || !country.isEmpty() && !asn.isEmpty())
      return discovered(country, asn, legacy, capacity);
    try {
      return GeoStore.withCurrent(
          dir,
          meta -> {
            String c = selected(meta, dir, "country", country), a = selected(meta, dir, "asn", asn);
            GeoIP g = GeoIP.open(c, a, null, capacity);
            try {
              apply(g, meta, country, asn);
              return new Opened(g, List.of());
            } catch (RuntimeException ex) {
              if (g != null) g.close();
              throw ex;
            }
          });
    } catch (GeoStore.NotInstalled ex) {
      return discovered(country, asn, legacy, capacity);
    } catch (IOException ex) {
      return new Opened(
          GeoIP.open(country, asn, null, capacity),
          List.of(
              "Managed GeoIP unavailable; analysis continues without automatic GeoIP: "
                  + ex.getMessage()));
    }
  }

  private static Opened discovered(String country, String asn, Path legacy, int capacity)
      throws IOException {
    GeoIP g = GeoIP.open(country, asn, legacy, capacity);
    if (g == null) return new Opened(null, List.of());
    var warnings = List.copyOf(g.warnings);
    g.warnings.clear();
    if (!g.hasReaders()) {
      g.close();
      g = null;
    }
    return new Opened(g, warnings);
  }

  private static String selected(Map<String, Object> meta, Path dir, String role, String explicit) {
    if (!explicit.isEmpty()) return explicit;
    for (var d : Json.rows(Json.obj(meta.get("current")).get("databases")))
      if (role.equals(d.get("role"))) return dir.resolve((String) d.get("file")).toString();
    return "";
  }

  private static void apply(GeoIP g, Map<String, Object> meta, String country, String asn) {
    var current = Json.obj(meta.get("current"));
    for (var row : g.metadata()) {
      if ("country".equals(row.get("role")) && !country.isEmpty()
          || "asn".equals(row.get("role")) && !asn.isEmpty()) continue;
      for (var d : Json.rows(current.get("databases")))
        if (d.get("role").equals(row.get("role"))) {
          row.put("version", d.get("version"));
          row.put("downloaded_at", d.get("downloaded_at"));
          row.put("source_url", d.get("url"));
          row.put("generation", current.get("id"));
          row.put("last_checked_at", meta.get("last_checked_at"));
        }
    }
  }
}
