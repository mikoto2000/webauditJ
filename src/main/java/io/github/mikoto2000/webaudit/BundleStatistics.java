package io.github.mikoto2000.webaudit;

import java.io.*;
import java.util.*;

/** Streaming whole-input statistics remain independent of evidence spool capacity. */
final class BundleStatistics {
  final int max;
  final boolean geo;
  final Map<String, Map<String, Map<String, Object>>> tables = new TreeMap<>();
  final Set<String> pairs = new HashSet<>();
  final Map<String, Long> geoStatuses = new TreeMap<>();
  final BundleNumeric bytes = new BundleNumeric("bytes"), duration = new BundleNumeric("seconds");
  final BundleTimeline timeline;
  long total;
  boolean truncated;

  BundleStatistics(int max, boolean geo) {
    this.max = max;
    this.geo = geo;
    timeline = new BundleTimeline(max);
  }

  Map<String, String> dimensions(Map<String, Object> snapshot, Event e) {
    var values = new LinkedHashMap<String, String>();
    values.put("method", e.method);
    values.put("protocol", e.protocol);
    values.put("status", e.status == null ? null : e.status.toString());
    values.put("status_class", e.status == null ? null : e.status / 100 + "xx");
    values.put("ip", e.ip);
    values.put("host", e.host);
    values.put("uri", e.path);
    values.put("user_agent", e.ua);
    values.put("log_type", e.logType);
    if (geo) {
      var info =
          snapshot.get("geoip") == null
              ? Map.<String, Object>of()
              : Json.obj(snapshot.get("geoip"));
      values.put(
          "country", info.get("country_code") == null ? null : info.get("country_code").toString());
      values.put("asn", info.get("asn") == null ? null : info.get("asn").toString());
    }
    return values;
  }

  Map<String, Object> row(String dim, String value, boolean admit) {
    String key = value == null ? "missing" : Bundle.id("VALUE-", value);
    var table = tables.get(dim);
    if (table == null) {
      if (!admit) return null;
      table = new LinkedHashMap<>();
      tables.put(dim, table);
    }
    var row = table.get(key);
    if (row != null) return row;
    if (!admit) return table.get("other");
    long retained = table.size() - (table.containsKey("other") ? 1 : 0);
    boolean other = retained >= max;
    if (other) {
      truncated = true;
      row = table.get("other");
      if (row != null) return row;
      key = "other";
    }
    int limit =
        switch (dim) {
          case "method", "protocol" -> 128;
          case "user_agent" -> 512;
          case "host" -> 255;
          default -> 1024;
        };
    String label = value == null ? null : Core.clip(value, limit);
    boolean cut = !Objects.equals(value, label);
    truncated |= cut;
    row =
        Json.map(
            "key",
            key,
            "value",
            other ? null : label,
            "name",
            null,
            "organization",
            null,
            "requests",
            0L,
            "suspicious_requests",
            0L,
            "request_percent",
            0.0,
            "suspicious_within_group_percent",
            0.0,
            "unique_ips",
            !other && (dim.equals("country") || dim.equals("asn")) ? 0L : null,
            "unique_ip_quality",
            !other && (dim.equals("country") || dim.equals("asn")) ? "exact" : "unavailable",
            "other",
            other,
            "label_truncated",
            cut,
            "count_quality",
            "exact");
    table.put(key, row);
    return row;
  }

  static void increment(Map<String, Object> row, String field) {
    row.put(field, Json.number(row.get(field)) + 1);
  }

  void observe(Map<String, Object> snapshot, Event e) {
    total++;
    var info = snapshot.get("geoip") == null ? null : Json.obj(snapshot.get("geoip"));
    for (var dimension : dimensions(snapshot, e).entrySet()) {
      String dim = dimension.getKey();
      var row = row(dim, dimension.getValue(), true);
      increment(row, "requests");
      if (geo && (dim.equals("country") || dim.equals("asn")) && info != null) {
        String pair = dim + "|" + row.get("key") + "|" + e.ip;
        if (row.get("unique_ips") != null && !pairs.contains(pair)) {
          if (pairs.size() < max) {
            pairs.add(pair);
            increment(row, "unique_ips");
          } else {
            row.put("unique_ip_quality", "lower_bound");
            truncated = true;
          }
        }
        if (!Json.bool(row.get("other"))) {
          String field = dim.equals("country") ? "name" : "organization",
              source = dim.equals("country") ? "country_name" : "asn_organization";
          if (info.get(source) != null) {
            String name = info.get(source).toString(), label = Core.clip(name, 255);
            row.put(field, label);
            if (!name.equals(label)) {
              row.put("label_truncated", true);
              truncated = true;
            }
          }
        }
      }
    }
    if (geo && info != null)
      for (String role : List.of("country", "asn"))
        geoStatuses.merge(role + ":" + Json.string(info.get(role + "_status")), 1L, Long::sum);
    bytes.add(e.bytes == null ? null : e.bytes.doubleValue(), false);
    duration.add(
        snapshot.get("request_duration") instanceof Number n ? n.doubleValue() : null,
        Json.bool(snapshot.get("invalid_duration")));
    timeline.observe(e, false);
  }

  void suspicious(Map<String, Object> snapshot, Event e) {
    for (var dim : dimensions(snapshot, e).entrySet()) {
      var row = row(dim.getKey(), dim.getValue(), false);
      if (row != null) increment(row, "suspicious_requests");
    }
    timeline.suspicious(e);
  }

  Map<String, Object> model(Map<String, Object> report) {
    timeline.finish();
    truncated |= timeline.truncated;
    var dimensions = new TreeMap<String, List<Map<String, Object>>>();
    for (var table : tables.entrySet()) {
      var values = new ArrayList<Map<String, Object>>();
      for (var original : table.getValue().values()) {
        var row = new LinkedHashMap<>(original);
        row.put(
            "suspicious_count_quality",
            Json.bool(report.get("evidence_complete")) ? "exact" : "lower_bound");
        long requests = Json.number(row.get("requests")),
            suspicious = Json.number(row.get("suspicious_requests"));
        row.put("request_percent", total == 0 ? 0.0 : requests * 100.0 / total);
        row.put(
            "suspicious_within_group_percent", requests == 0 ? 0.0 : suspicious * 100.0 / requests);
        values.add(row);
      }
      values.sort(
          Comparator.comparingLong((Map<String, Object> r) -> -Json.number(r.get("requests")))
              .thenComparing(r -> (String) r.get("key")));
      dimensions.put(table.getKey(), values);
    }
    long unique = 0, suspiciousIPs = 0;
    String uniqueQuality = "exact";
    for (var row : dimensions.getOrDefault("ip", List.of()))
      if (Json.bool(row.get("other"))) uniqueQuality = "lower_bound";
      else if (row.get("value") != null) {
        unique++;
        if (Json.number(row.get("suspicious_requests")) > 0) suspiciousIPs++;
      }
    var attacks = new TreeMap<String, Long>();
    var catalog = new HashMap<String, Map<String, Object>>();
    for (var rule : BundleCoverage.rows(report.get("analysis_rules")))
      catalog.put(BundleCoverage.key((String) rule.get("engine"), (String) rule.get("id")), rule);
    for (var coverage : BundleCoverage.rows(report.get("coverage"))) {
      var engines = BundleRequests.strings(coverage.get("engines"));
      var ids = BundleRequests.strings(coverage.get("rule_ids"));
      if (!Json.string(coverage.get("id")).startsWith("RULE-")
          || engines.size() != 1
          || ids.size() != 1
          || coverage.get("detections") == null) continue;
      var rule = catalog.get(BundleCoverage.key(engines.getFirst(), ids.getFirst()));
      String category = rule == null ? "" : Json.string(rule.get("category"));
      attacks.merge(
          engines.getFirst() + ":" + (category.isEmpty() ? "unclassified" : category),
          Json.number(coverage.get("detections")),
          Long::sum);
    }
    long suspicious = Json.number(Json.obj(report.get("evidence")).get("suspicious_requests"));
    return Json.map(
        "population",
        "successfully parsed, non-deduplicated source observations; source records are not verified"
            + " unique network transactions",
        "total_requests",
        total,
        "unique_ips",
        unique,
        "unique_ip_quality",
        uniqueQuality,
        "suspicious_ips",
        suspiciousIPs,
        "suspicious_count_quality",
        Json.bool(report.get("evidence_complete")) ? "exact" : "lower_bound",
        "suspicious_percent",
        total == 0 ? null : suspicious * 100.0 / total,
        "dimensions",
        dimensions,
        "timeline",
        timeline.rows(),
        "timeline_resolution_seconds",
        timeline.resolution,
        "unknown_time_requests",
        timeline.unknown,
        "omitted_timeline_requests",
        timeline.omitted,
        "response_bytes",
        bytes.map(),
        "request_duration",
        duration.map(),
        "geoip_enabled",
        geo,
        "geo_lookup_statuses",
        geoStatuses,
        "attack_detections",
        attacks,
        "truncated",
        truncated,
        "notes",
        List.of(
            "No observations in a time bin do not establish missing logs or downtime",
            "Response byte sums and means use floating-point arithmetic; rounding is possible",
            "Counts across perspectives, rules and engines overlap and must not be summed as unique"
                + " requests"));
  }

  void write(BundleWriter writer, Map<String, Object> statistics) throws IOException {
    var dimensions = Json.obj(statistics.get("dimensions"));
    List<String> header =
        List.of(
            "key",
            "value",
            "name",
            "organization",
            "missing",
            "other",
            "requests",
            "suspicious_requests",
            "suspicious_count_quality",
            "request_percent",
            "suspicious_within_group_percent",
            "unique_ips",
            "unique_ip_quality",
            "label_truncated",
            "count_quality");
    for (String dim :
        List.of(
            "status",
            "status_class",
            "method",
            "ip",
            "host",
            "uri",
            "user_agent",
            "country",
            "asn",
            "log_type",
            "protocol"))
      writer.csv(
          "statistics/" + dim.replace('_', '-') + "-summary.csv",
          header,
          write -> {
            for (var row : BundleCoverage.rows(dimensions.get(dim))) {
              var values = new ArrayList<String>();
              for (String field : header)
                values.add(
                    field.equals("missing")
                        ? Boolean.toString(row.get("value") == null && !Json.bool(row.get("other")))
                        : Json.string(row.get(field)));
              write.accept(values.toArray(String[]::new));
            }
          });
    writer.csv(
        "statistics/numeric-summary.csv",
        List.of(
            "metric",
            "unit",
            "count",
            "missing",
            "invalid",
            "sum",
            "sum_quality",
            "minimum",
            "maximum",
            "mean"),
        write -> {
          for (String metric : List.of("response_bytes", "request_duration")) {
            var row = Json.obj(statistics.get(metric));
            write.accept(
                metric,
                Bundle.cell(row, "unit"),
                Bundle.cell(row, "count"),
                Bundle.cell(row, "missing"),
                Bundle.cell(row, "invalid"),
                Bundle.cell(row, "sum"),
                Bundle.cell(row, "sum_quality"),
                Bundle.cell(row, "min"),
                Bundle.cell(row, "max"),
                Bundle.cell(row, "mean"));
          }
        });
    writer.csv(
        "statistics/timeline.csv",
        List.of(
            "time_utc",
            "resolution_seconds",
            "requests",
            "suspicious_requests",
            "4xx",
            "5xx",
            "suspicious_count_quality"),
        write -> {
          for (var row : BundleCoverage.rows(statistics.get("timeline")))
            write.accept(
                Bundle.cell(row, "time"),
                Bundle.cell(statistics, "timeline_resolution_seconds"),
                Bundle.cell(row, "requests"),
                Bundle.cell(row, "suspicious_requests"),
                Bundle.cell(row, "errors_4xx"),
                Bundle.cell(row, "errors_5xx"),
                Bundle.cell(statistics, "suspicious_count_quality"));
        });
  }
}
