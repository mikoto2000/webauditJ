package io.github.mikoto2000.webaudit;

import static io.github.mikoto2000.webaudit.Core.*;

import com.maxmind.db.Reader;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.*;
import java.util.*;

public final class GeoIP implements AutoCloseable {
  final List<String> warnings = new ArrayList<>();
  private Reader country, asn;
  private final List<Map<String, Object>> metadata = new ArrayList<>();
  private final LinkedHashMap<String, Map<String, Object>> cache =
      new LinkedHashMap<>(16, 0.75f, true);
  private int capacity;
  long calls, hits, peerHits, lookups, skipped;

  public static GeoIP open(String country, String asn, Path legacyDir, int capacity)
      throws IOException {
    GeoIP g = new GeoIP();
    g.capacity = capacity > 0 ? capacity : 4096;
    for (String role : List.of("country", "asn")) {
      String explicit = role.equals("country") ? country : asn;
      Path path = explicit.isEmpty() ? null : Path.of(explicit);
      if (path == null && legacyDir != null) {
        Path fixed = legacyDir.resolve(role + ".mmdb");
        if (Files.exists(fixed)) path = fixed;
        else if (Files.isDirectory(legacyDir)) {
          try (var files = Files.list(legacyDir)) {
            path =
                files
                    .filter(p ->
                        p.getFileName().toString().startsWith("dbip-" + role + "-lite-")
                            && p.getFileName().toString().endsWith(".mmdb"))
                    .max(Comparator.comparing(Path::toString))
                    .orElse(null);
          }
        }
      }
      if (path == null) continue;
      Reader db = null;
      try {
        db = new Reader(path.toFile(), readerMode());
        verify(db);
        String type = db.getMetadata().databaseType(), low = Normalizer.lower(type);
        if (role.equals("country") && low.contains("asn") && !low.contains("country")
            || role.equals("asn")
                && (low.contains("country") || low.contains("city"))
                && !low.contains("asn"))
          throw new IOException("wrong database type " + type + " for " + role);
        if (role.equals("country")) g.country = db;
        else g.asn = db;
        Instant build =
            db.getMetadata().buildEpoch().signum() > 0 ? db.getMetadata().buildTime() : null;
        String provider = low.startsWith("dbip-") ? "DB-IP" : "unknown",
            license =
                low.startsWith("dbip-") && low.contains("lite")
                    ? "CC BY 4.0; IP Geolocation by DB-IP (https://db-ip.com)"
                    : "unknown (see database provider terms)";
        g.metadata.add(
            Json.map(
                "role",
                role,
                "file",
                path.toString(),
                "provider",
                provider,
                "type",
                type,
                "updated_at",
                build == null ? null : build.atOffset(ZoneOffset.UTC).toLocalDate().toString(),
                "license",
                license,
                "version",
                null,
                "downloaded_at",
                null,
                "build_time",
                Times.instant(build),
                "source_url",
                null,
                "generation",
                null,
                "last_checked_at",
                null));
      } catch (IOException | RuntimeException ex) {
        if (db != null) db.close();
        String message = "GeoIP " + role + " database \"" + path + "\": " + ex.getMessage();
        if (!explicit.isEmpty()) {
          g.close();
          throw new IOException(message, ex);
        }
        g.warnings.add(message + "; automatic database ignored");
      }
    }
    return g.country == null && g.asn == null && g.warnings.isEmpty() ? null : g;
  }

  static Reader.FileMode readerMode() {
    return System.getProperty("os.name").startsWith("Windows")
        ? Reader.FileMode.MEMORY
        : Reader.FileMode.MEMORY_MAPPED;
  }

  static void verify(Reader db) throws IOException {
    try {
      var networks = db.networks(Object.class);
      while (networks.hasNext()) networks.next();
    } catch (Exception ex) {
      throw new IOException("MMDB validation failed", ex);
    }
  }

  private static Map<String, Object> blank(String classification) {
    String
        status =
            classification.equals("invalid")
                ? "invalid_ip"
                : classification.equals("public") ? "db_not_installed" : "non_public",
        role = classification.equals("public") ? "db_not_installed" : "not_queried";
    return Json.map(
        "status",
        status,
        "country_status",
        role,
        "asn_status",
        role,
        "classification",
        classification,
        "country_code",
        null,
        "country_name",
        null,
        "asn",
        null,
        "asn_organization",
        null);
  }

  public Map<String, Object> lookup(String address) {
    String ip = IP.canonical(address), classification = IPClassifier.classify(address);
    var x = blank(classification);
    if (!classification.equals("public")) return x;
    calls++;
    if (cache.containsKey(ip)) {
      hits++;
      return cache.get(ip);
    }
    if (country != null) {
      x.put("country_status", "not_found");
      lookups++;
      try {
        Map<?, ?> r = country.get(IP.parse(ip), Map.class);
        if (r != null && r.get("country") != null && !(r.get("country") instanceof Map)) {
          throw new IOException("invalid country schema");
        }
        if (r != null && r.get("country") instanceof Map<?, ?> c) {
          Object code = c.get("iso_code"), names = c.get("names");
          if (code != null && !(code instanceof String) || names != null && !(names instanceof Map))
            throw new IOException("invalid country schema");
          if (names instanceof Map<?, ?> m) {
            for (Object value : m.values()) {
              if (!(value instanceof String)) throw new IOException("invalid country names");
            }
          }
          if (code instanceof String value && !value.isEmpty()) x.put("country_code", value);
          if (x.get("country_code") != null || names instanceof Map<?, ?> m && !m.isEmpty())
            x.put("country_status", "found");
          if (names instanceof Map<?, ?> m
              && m.get("en") instanceof String value
              && !value.isEmpty()) x.put("country_name", value);
        }
      } catch (IOException | RuntimeException ex) {
        x.put("country_status", "read_error");
        lookupError("country", ex);
      }
    }
    if (asn != null) {
      x.put("asn_status", "not_found");
      lookups++;
      try {
        Map<?, ?> r = asn.get(IP.parse(ip), Map.class);
        if (r != null) {
          Object number = r.get("autonomous_system_number"),
              org = r.get("autonomous_system_organization");
          if (number != null && !MmdbSchema.validAsn(number)
              || org != null && !(org instanceof String))
            throw new IOException("invalid ASN schema");
          if (number != null) x.put("asn", ((Number) number).longValue());
          if (org instanceof String value && !value.isEmpty()) x.put("asn_organization", value);
          if (x.get("asn") != null || x.get("asn_organization") != null)
            x.put("asn_status", "found");
        }
      } catch (IOException | RuntimeException ex) {
        x.put("asn_status", "read_error");
        lookupError("asn", ex);
      }
    }
    if (x.get("country_status").equals("read_error") || x.get("asn_status").equals("read_error"))
      x.put("status", "read_error");
    else if (x.get("country_status").equals("found") || x.get("asn_status").equals("found"))
      x.put("status", "found");
    else if (country != null || asn != null) x.put("status", "not_found");
    if (cache.size() >= capacity) cache.remove(cache.keySet().iterator().next());
    cache.put(ip, x);
    return x;
  }

  private void lookupError(String role, Exception ex) {
    if (warnings.size() < 10)
      unique(warnings, "GeoIP " + role + " lookup failed: " + ex.getMessage());
  }

  public List<Map<String, Object>> metadata() {
    return List.copyOf(metadata);
  }

  boolean hasReaders() {
    return country != null || asn != null;
  }

  Map<String, Object> metrics() {
    return Json.map(
        "public_lookup_calls",
        calls,
        "lru_hits",
        hits,
        "peer_cache_hits",
        peerHits,
        "reader_lookups",
        lookups,
        "cached_ips",
        cache.size(),
        "untracked_requests",
        skipped,
        "cache_hit_rate",
        calls + peerHits == 0 ? 0.0 : (double) (hits + peerHits) / (calls + peerHits));
  }

  public void close() throws IOException {
    IOException error = null;
    for (Reader reader : new Reader[] {country, asn})
      if (reader != null)
        try {
          reader.close();
        } catch (IOException ex) {
          error = ex;
        }
    if (error != null) throw error;
  }
}
