package io.github.mikoto2000.webaudit;

import java.time.*;
import java.util.*;

/** One adaptive UTC timeline shared by whole-input and per-case statistics. */
final class BundleTimeline {
  final int max;
  long resolution = 60, unknown, omitted;
  boolean truncated;
  Instant first, last;
  TreeMap<Long, long[]> bins = new TreeMap<>();
  static final long MINIMUM =
      OffsetDateTime.of(0, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).toEpochSecond();

  BundleTimeline(int max) {
    this.max = max;
  }

  static long floor(long second, long width) {
    return Math.max(MINIMUM, Math.floorDiv(second, width) * width);
  }

  void coarsen() {
    long next =
        switch ((int) resolution) {
          case 60 -> 3600;
          case 3600 -> 86400;
          case 86400 -> 604800;
          case 604800 -> 2592000;
          case 2592000 -> 31536000;
          default -> resolution * 10;
        };
    var merged = new TreeMap<Long, long[]>();
    for (var entry : bins.entrySet()) {
      var row = merged.computeIfAbsent(floor(entry.getKey(), next), _ -> new long[4]);
      for (int i = 0; i < 4; i++) row[i] += entry.getValue()[i];
    }
    bins = merged;
    resolution = next;
  }

  void observe(Event e, boolean suspicious) {
    if (e.timezoneUnknown) {
      unknown++;
      return;
    }
    Instant time = e.time.toInstant();
    if (first == null || time.isBefore(first)) first = time;
    if (last == null || time.isAfter(last)) last = time;
    long bin = floor(time.getEpochSecond(), resolution);
    while (!bins.containsKey(bin) && bins.size() >= max && resolution < (1L << 40)) {
      coarsen();
      bin = floor(time.getEpochSecond(), resolution);
    }
    if (!bins.containsKey(bin) && bins.size() >= max) {
      omitted++;
      truncated = true;
      return;
    }
    var row = bins.computeIfAbsent(bin, _ -> new long[4]);
    row[0]++;
    if (suspicious) row[1]++;
    if (e.status != null && e.status >= 400 && e.status < 500) row[2]++;
    if (e.status != null && e.status >= 500 && e.status < 600) row[3]++;
  }

  void suspicious(Event e) {
    if (!e.timezoneUnknown) {
      var row = bins.get(floor(e.time.toEpochSecond(), resolution));
      if (row != null) row[1]++;
    }
  }

  void finish() {
    if (first == null || last == null) return;
    var span = Duration.between(first, last);
    long target =
        span.compareTo(Duration.ofDays(60)) > 0
            ? 86400
            : span.compareTo(Duration.ofDays(2)) > 0 ? 3600 : 60;
    while (resolution < target) coarsen();
  }

  List<Map<String, Object>> rows() {
    var out = new ArrayList<Map<String, Object>>();
    for (var entry : bins.entrySet()) {
      var n = entry.getValue();
      out.add(
          Json.map(
              "time",
              Times.instant(Instant.ofEpochSecond(entry.getKey())),
              "requests",
              n[0],
              "suspicious_requests",
              n[1],
              "errors_4xx",
              n[2],
              "errors_5xx",
              n[3]));
    }
    return out;
  }
}
