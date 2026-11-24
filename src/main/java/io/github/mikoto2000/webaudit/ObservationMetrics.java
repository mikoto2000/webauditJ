package io.github.mikoto2000.webaudit;

import java.time.*;
import java.util.*;

/** Bounded per-finding/group observations; no full request collections. */
final class ObservationMetrics {
  long requests, direct, related, detections, bytesCount;
  double bytesSum;
  Long bytesMin, bytesMax;
  OffsetDateTime first, last;
  final Map<String, Long> statuses = new TreeMap<>(), methods = new TreeMap<>();
  final Map<String, Map<String, Object>> uris = new LinkedHashMap<>();
  boolean truncated;
  final BundleTimeline timeline = new BundleTimeline(64);

  void observe(Event e, boolean isDirect, boolean isRelated) {
    timeline.observe(e, isDirect);
    requests++;
    if (isDirect) direct++;
    if (isRelated) related++;
    statuses.merge(e.status == null ? "unknown" : e.status.toString(), 1L, Long::sum);
    String method = e.method == null ? "unknown" : Core.clip(e.method, 128);
    if (!Objects.equals(method, e.method) && e.method != null) truncated = true;
    if (!methods.containsKey(method) && methods.size() >= 64) {
      method = "(other)";
      truncated = true;
    }
    methods.merge(method, 1L, Long::sum);
    String key = e.target.isEmpty() ? "missing" : Bundle.id("", e.target);
    var row = uris.get(key);
    if (row == null) {
      boolean other =
          uris.values().stream()
                      .filter(r -> !Json.bool(r.get("other")) && r.get("value") != null)
                      .count()
                  >= 8
              && !e.target.isEmpty();
      if (other) {
        key = "other";
        truncated = true;
        row = uris.get(key);
      }
      if (row == null) {
        String value = e.target.isEmpty() ? null : Core.clip(e.target, 1024);
        if (!Objects.equals(value, e.target) && !e.target.isEmpty()) truncated = true;
        row =
            Json.map(
                "key",
                key,
                "value",
                other ? null : value,
                "other",
                other,
                "requests",
                0L,
                "label_truncated",
                !e.target.isEmpty() && !e.target.equals(value),
                "count_quality",
                "exact");
        uris.put(key, row);
      }
    }
    row.put("requests", Json.number(row.get("requests")) + 1);
    if (e.bytes != null) {
      bytesCount++;
      bytesSum += e.bytes;
      if (bytesMin == null || e.bytes < bytesMin) bytesMin = e.bytes;
      if (bytesMax == null || e.bytes > bytesMax) bytesMax = e.bytes;
    }
    if (!e.timezoneUnknown) {
      if (first == null || e.time.isBefore(first)) first = e.time;
      if (last == null || e.time.isAfter(last)) last = e.time;
    }
  }

  Map<String, Object> bytes() {
    return Json.map(
        "count",
        bytesCount,
        "missing",
        requests - bytesCount,
        "invalid",
        0L,
        "sum",
        bytesCount == 0 ? null : bytesSum,
        "sum_quality",
        bytesCount == 0 ? "unavailable" : "finite",
        "min",
        bytesMin,
        "max",
        bytesMax,
        "mean",
        bytesCount == 0 ? null : bytesSum / bytesCount,
        "unit",
        "bytes");
  }

  Map<String, Object> map(String findingID) {
    long unique =
        uris.values().stream()
            .filter(r -> r.get("value") != null && !Json.bool(r.get("other")))
            .count();
    boolean missing = uris.values().stream().anyMatch(r -> r.get("value") == null);
    Double rate =
        first != null && last != null && last.isAfter(first)
            ? requests
                / (Duration.between(first, last).getSeconds()
                    + Duration.between(first, last).getNano() / 1e9)
            : null;
    timeline.finish();
    return Json.map(
        "finding_id",
        findingID,
        "requests",
        requests,
        "direct_requests",
        direct,
        "related_requests",
        related,
        "detections",
        detections,
        "status_counts",
        statuses,
        "methods",
        methods,
        "uri_samples",
        uris.values().stream()
            .filter(r -> r.get("value") != null)
            .map(r -> r.get("value"))
            .toList(),
        "uri_samples_truncated",
        truncated,
        "uri_statistics",
        new ArrayList<>(uris.values()),
        "retained_unique_uris",
        unique,
        "unique_uri_quality",
        unique == 0 ? "unavailable" : missing ? "lower_bound" : "exact",
        "bytes_count",
        bytesCount,
        "bytes_sum",
        bytesSum,
        "bytes_min",
        bytesMin,
        "bytes_max",
        bytesMax,
        "first",
        Times.text(first),
        "last",
        Times.text(last),
        "request_rate_per_second",
        rate,
        "timeline",
        timeline.rows(),
        "timeline_resolution_seconds",
        timeline.resolution);
  }
}
