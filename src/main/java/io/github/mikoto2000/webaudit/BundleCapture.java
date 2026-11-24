package io.github.mikoto2000.webaudit;

import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;

/** Optional observations from the original parser stream; no duplicate analysis. */
final class BundleCapture {
  final Options options;
  final Map<String, Map<String, Object>> inputs = new LinkedHashMap<>();
  final List<Map<String, Object>> diagnostics = new ArrayList<>(), excluded = new ArrayList<>();
  boolean diagnosticsTruncated;

  BundleCapture(Options options) {
    this.options = options;
  }

  static String path(Path p) {
    return p.toAbsolutePath().normalize().toString();
  }

  Map<String, Object> begin(Path p) {
    String name = path(p);
    var existing = inputs.get(name);
    if (existing != null) return existing;
    var row =
        Json.map(
            "id",
            Bundle.id("FILE-", name),
            "path",
            name,
            "size_bytes",
            null,
            "sha256",
            null,
            "hash_scope",
            "original_file_bytes",
            "hash_status",
            "unavailable",
            "compression",
            "unknown",
            "first",
            null,
            "last",
            null,
            "total_lines",
            0L,
            "parsed",
            0L,
            "unparsed",
            0L,
            "excluded",
            0L,
            "status",
            "completed",
            "truncated",
            false,
            "changed_during_analysis",
            false,
            "count_quality",
            "exact",
            "formats",
            new TreeSet<String>(),
            "log_types",
            new TreeSet<String>(),
            "available_fields",
            new TreeSet<String>(),
            "timezones",
            new TreeSet<String>(),
            "timezones_truncated",
            false);
    inputs.put(name, row);
    try {
      if (Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
        row.put("size_bytes", Files.size(p));
        try (var in = Files.newInputStream(p)) {
          row.put("compression", in.read() == 0x1f && in.read() == 0x8b ? "gzip" : "none");
        }
        String hash = Bundle.hash(p, options.maxFileBytes);
        row.put("sha256", hash);
        row.put("hash_status", hash == null ? "size_limit" : "complete");
      }
    } catch (IOException ignored) {
    }
    return row;
  }

  void line(Path p) {
    increment(begin(p), "total_lines");
  }

  void bad(Path p, long line, String reason) {
    increment(begin(p), "unparsed");
    diagnostic(diagnostics, p, line, reason);
  }

  void blank(Path p, long line) {
    increment(begin(p), "excluded");
    diagnostic(excluded, p, line, "blank line");
  }

  void diagnostic(List<Map<String, Object>> rows, Path p, long line, String reason) {
    if (rows.size() >= options.maxKeys) {
      diagnosticsTruncated = true;
      return;
    }
    rows.add(
        Json.map(
            "file_id",
            Bundle.id("FILE-", path(p)),
            "source_file",
            path(p),
            "source_line",
            line,
            "reason",
            reason));
  }

  static void increment(Map<String, Object> row, String key) {
    row.put(key, Json.number(row.get(key)) + 1);
  }

  @SuppressWarnings("unchecked")
  void event(Event e) {
    var row = begin(Path.of(e.file));
    increment(row, "parsed");
    if (!e.timezoneUnknown) {
      String time = Times.text(e.time);
      String first = (String) row.get("first"), last = (String) row.get("last");
      if (first == null || e.time.isBefore(Times.parse(first))) row.put("first", time);
      if (last == null || e.time.isAfter(Times.parse(last))) row.put("last", time);
    }
    var zones = (Set<String>) row.get("timezones");
    String zone =
        e.timezoneUnknown ? "unknown" : "UTC" + e.time.getOffset().getId().replace("Z", "+00:00");
    if (zones.contains(zone) || zones.size() < 64) zones.add(zone);
    else row.put("timezones_truncated", true);
    ((Set<String>) row.get("formats")).add(e.format);
    ((Set<String>) row.get("log_types")).add(e.logType);
    var fields = (Set<String>) row.get("available_fields");
    fields.add("ip");
    fields.add("recorded_time");
    if (!e.timezoneUnknown) fields.add("time");
    for (var entry :
        Json.map(
                "target",
                e.target,
                "method",
                e.method,
                "protocol",
                e.protocol,
                "user_agent",
                e.ua,
                "referer",
                e.referer,
                "status",
                e.status,
                "bytes",
                e.bytes,
                "host",
                e.host,
                "auth_failure",
                e.authFailure ? true : null)
            .entrySet())
      if (entry.getValue() != null && !entry.getValue().toString().isEmpty())
        fields.add(entry.getKey());
  }

  void duplicate(Path p, String original) {
    var row = begin(p);
    var old = inputs.get(original);
    if (old != null) {
      row.put("total_lines", old.get("total_lines"));
      row.put("excluded", old.get("total_lines"));
    }
    row.put("duplicate_of", original);
    row.put("status", "excluded_duplicate");
    finish(p, null);
  }

  void finish(Path p, String error) {
    var row = begin(p);
    if (error != null && !error.isEmpty()) {
      row.put("error", error);
      row.put("status", "partial");
      row.put("truncated", error.toLowerCase(Locale.ROOT).contains("limit"));
    }
    try {
      boolean sizeChanged =
          row.get("size_bytes") != null && Files.size(p) != Json.number(row.get("size_bytes"));
      String after = Bundle.hash(p, options.maxFileBytes);
      if (after == null || !Objects.equals(row.get("sha256"), after)) {
        row.put(
            "changed_during_analysis", sizeChanged || after != null && row.get("sha256") != null);
        row.put("status", "partial");
        row.put(
            "hash_status",
            after == null
                ? ("size_limit".equals(row.get("hash_status")) ? "size_limit" : "unavailable")
                : "changed");
      }
    } catch (IOException ex) {
      row.put("status", "partial");
      row.put("hash_status", "unavailable");
    }
    if (Json.number(row.get("unparsed")) > 0 || Json.bool(row.get("timezones_truncated")))
      row.put("status", "partial");
    if (!"completed".equals(row.get("status")) && !"excluded_duplicate".equals(row.get("status")))
      row.put("count_quality", "lower_bound");
  }
}
