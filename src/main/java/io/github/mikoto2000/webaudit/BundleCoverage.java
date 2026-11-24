package io.github.mikoto2000.webaudit;

import java.io.*;
import java.util.*;

/** Metadata and observers for existing rules, never an alternative detection engine. */
final class BundleCoverage {
  static final List<Map<String, Object>> ASPECTS = Json.rows(Json.resource("report-aspects.json"));
  final List<Map<String, Object>> rules = catalog();
  final Map<String, long[]> observations = new HashMap<>(), aspects = new HashMap<>();
  List<Signal> signals = List.of();
  Map<String, Boolean> ready = Map.of();

  static String key(String engine, String id) {
    return engine + "|" + id;
  }

  static List<Map<String, Object>> rows(Object value) {
    return value == null ? List.of() : Json.rows(value);
  }

  static List<Map<String, Object>> catalog() {
    var out = new ArrayList<Map<String, Object>>();
    for (var r : Json.rows(Json.resource("rules.json")))
      out.add(
          Json.map(
              "id",
              r.get("id"),
              "severity",
              r.get("severity"),
              "engine",
              "webaudit",
              "kind",
              "signature",
              "category",
              r.get("category"),
              "description",
              r.get("description"),
              "required_fields",
              r.get("required"),
              "condition",
              r.get("field") + ": " + r.get("pattern"),
              "supported",
              true,
              "enabled",
              true));
    for (var r : Json.rows(Json.resource("report-aggregate-rules.json")))
      out.add(new LinkedHashMap<>(r));
    for (var r : SourceMatcher.RULES) {
      String expression =
          Json.string(r.get("filter"))
              + " "
              + Json.string(r.get("groupby"))
              + " "
              + Json.string(r.get("distinct"));
      var required = new TreeSet<String>(List.of("ip", "recorded_time"));
      for (String token : List.of("http_path", "Parsed.request", "http_args", "file_name"))
        if (expression.contains(token)) required.add("target");
      for (var field :
          Map.of(
                  "status",
                  "http_status",
                  "method",
                  "http_verb",
                  "user_agent",
                  "http_user_agent",
                  "protocol",
                  "http_version",
                  "referer",
                  "http_referer",
                  "host",
                  "target_fqdn")
              .entrySet()) if (expression.contains(field.getValue())) required.add(field.getKey());
      String condition =
          Json.string(r.get("filter"))
              + "; capacity="
              + Json.number(r.get("capacity"))
              + "; cache_size="
              + Json.number(r.get("cache_size"))
              + "; leakspeed="
              + Json.string(r.get("leakspeed"))
              + "; blackhole="
              + Json.string(r.get("blackhole"))
              + "; groupby="
              + Json.string(r.get("groupby"))
              + "; distinct="
              + Json.string(r.get("distinct"));
      out.add(
          Json.map(
              "id",
              r.get("name"),
              "severity",
              "",
              "engine",
              "hub",
              "kind",
              r.get("type"),
              "category",
              "",
              "description",
              r.get("description"),
              "required_fields",
              List.copyOf(required),
              "condition",
              condition,
              "supported",
              r.get("supported"),
              "enabled",
              r.get("supported")));
    }
    for (var r : Json.rows(SourceMatcher.AURA.get("signatures")))
      out.add(
          Json.map(
              "id",
              r.get("id"),
              "severity",
              r.get("severity"),
              "engine",
              "aura",
              "kind",
              "signature",
              "category",
              r.get("id"),
              "description",
              r.get("description"),
              "required_fields",
              List.of("target"),
              "condition",
              r.get("pattern"),
              "supported",
              true,
              "enabled",
              true));
    out.add(
        rule(
            "scanner_ua",
            "aura",
            "signature",
            "Source scanner User-Agent match",
            List.of("user_agent"),
            Bundle.join(SourceMatcher.AURA.get("scanner_uas"))));
    out.add(
        rule(
            "dangerous_method",
            "aura",
            "signature",
            "Source dangerous HTTP method",
            List.of("method"),
            Bundle.join(SourceMatcher.AURA.get("methods"))));
    out.add(
        rule(
            "geoip-similarity",
            "geoip",
            "context",
            "Multi-IP similarity within one ASN",
            List.of("ip", "time", "target"),
            "known shared ASN + path + host when known + category + fixed five-minute UTC interval;"
                + " contextual hint only"));
    out.sort(
        Comparator.comparing((Map<String, Object> r) -> (String) r.get("engine"))
            .thenComparing(r -> (String) r.get("id")));
    return out;
  }

  static Map<String, Object> rule(
      String id,
      String engine,
      String kind,
      String description,
      List<String> required,
      String condition) {
    return Json.map(
        "id",
        id,
        "engine",
        engine,
        "kind",
        kind,
        "description",
        description,
        "category",
        "",
        "severity",
        "",
        "required_fields",
        required,
        "condition",
        condition,
        "supported",
        true,
        "enabled",
        true);
  }

  static boolean eligible(Event e, Object fields) {
    for (Object field : (Collection<?>) fields) {
      boolean ok =
          switch (field.toString()) {
            case "ip" -> !e.ip.isEmpty();
            case "recorded_time" -> !e.timezoneUnknown || e.wallTime != null;
            case "time" -> !e.timezoneUnknown;
            case "target" -> !e.target.isEmpty();
            case "method" -> e.method != null;
            case "protocol" -> e.protocol != null;
            case "status" -> e.status != null;
            case "bytes" -> e.bytes != null;
            case "user_agent" -> e.ua != null;
            case "referer" -> e.referer != null;
            case "host" -> e.host != null;
            default -> true;
          };
      if (!ok) return false;
    }
    return true;
  }

  void hit(String engine, String id) {
    long[] row = observations.computeIfAbsent(key(engine, id), _ -> new long[3]);
    row[1]++;
    row[2]++;
  }

  void observe(Event e, Signatures.Detection detection) {
    var matched = new HashSet<String>();
    for (var hit : detection.hits()) {
      String id = (String) hit.get("id");
      hit("webaudit", id);
      matched.add(id);
    }
    var eligible = new HashSet<String>();
    for (var rule : rules) {
      if (!Json.bool(rule.get("supported"))) continue;
      long[] row =
          observations.computeIfAbsent(
              key((String) rule.get("engine"), (String) rule.get("id")), _ -> new long[3]);
      if ((!"aura-analysis".equals(rule.get("engine")) || "http_access-log".equals(e.logType))
          && eligible(e, rule.get("required_fields"))) {
        row[0]++;
        if ("webaudit".equals(rule.get("engine"))) eligible.add((String) rule.get("id"));
      }
    }
    for (var aspect : ASPECTS) {
      long[] row = aspects.computeIfAbsent((String) aspect.get("id"), _ -> new long[3]);
      boolean applicable = false, hit = false;
      for (Object id : (List<?>) aspect.get("rules")) {
        applicable |= eligible.contains(id);
        if (matched.contains(id)) {
          hit = true;
          row[2]++;
        }
      }
      if (applicable) row[0]++;
      if (hit) row[1]++;
    }
  }

  static void status(Map<String, Object> row, boolean supported, boolean partial, boolean ready) {
    row.put("count_quality", "exact");
    row.put("complete", supported && !partial && ready);
    if (!supported) {
      row.put("status", "unsupported");
      row.put("evaluation", "not_supported");
      row.put("complete", false);
      for (String field : List.of("eligible_requests", "detected_requests", "detections"))
        row.put(field, null);
      row.put("count_quality", "unavailable");
      return;
    }
    if (!ready
        || row.get("eligible_requests") == null
        || Json.number(row.get("eligible_requests")) == 0) {
      String state = Json.bool(row.get("has_detections")) ? "partial" : "unable";
      row.put("status", state);
      row.put("evaluation", state);
      row.put("complete", false);
      row.put("count_quality", "unavailable");
      return;
    }
    if (partial) {
      row.put("status", "partial");
      row.put("evaluation", "partial");
      row.put("complete", false);
      row.put("count_quality", "lower_bound");
      return;
    }
    row.put("evaluation", "evaluated");
    row.put("status", Json.bool(row.get("has_detections")) ? "detected" : "no_detection");
  }

  static Map<String, Object> coverageRow(
      String id, String name, List<String> ids, List<String> engines, long[] counts) {
    return Json.map(
        "id",
        id,
        "name",
        name,
        "description",
        name,
        "rule_ids",
        ids,
        "engines",
        engines,
        "eligible_requests",
        counts[0],
        "detected_requests",
        counts[1],
        "related_requests",
        null,
        "detections",
        counts[2],
        "matched_candidates",
        counts[1],
        "has_detections",
        counts[1] > 0,
        "complete",
        false,
        "finding_ids",
        new ArrayList<String>(),
        "conditions",
        new ArrayList<String>(),
        "limitations",
        new ArrayList<String>());
  }

  @SuppressWarnings("unchecked")
  static List<String> strings(Map<String, Object> row, String field) {
    return (List<String>) row.get(field);
  }

  List<Map<String, Object>> build(Map<String, Object> report) {
    var analysis = Json.obj(report.get("analysis"));
    var counts = new HashMap<String, Long>();
    for (var signal : signals)
      counts.merge(key("webaudit", (String) signal.rule().get("id")), 1L, Long::sum);
    for (var pair :
        Map.of("hub", "upstream_alerts", "aura", "aura_matches", "aura-analysis", "aura_analysis")
            .entrySet())
      for (var alert : rows(analysis.get(pair.getValue())))
        counts.merge(key(pair.getKey(), (String) alert.get("rule_id")), 1L, Long::sum);
    if (analysis.get("geoip") != null)
      counts.put(
          key("geoip", "geoip-similarity"),
          (long) rows(Json.obj(analysis.get("geoip")).get("correlations")).size());
    long population =
        Json.number(analysis.get("requests")) - Json.number(analysis.get("duplicates"));
    var out = new ArrayList<Map<String, Object>>();
    var byRule = new HashMap<String, Map<String, Object>>();
    for (var rule : rules) {
      String engine = (String) rule.get("engine"),
          id = (String) rule.get("id"),
          key = key(engine, id);
      long[] ob = observations.getOrDefault(key, new long[3]);
      boolean signature = engine.equals("webaudit") && rule.get("kind").equals("signature");
      long count = signature ? ob[1] : counts.getOrDefault(key, 0L);
      var row =
          coverageRow(
              "RULE-" + engine + "-" + id,
              (String) rule.get("description"),
              List.of(id),
              List.of(engine),
              ob);
      row.put("detected_requests", signature ? ob[1] : null);
      row.put("detections", count);
      row.put("has_detections", count > 0);
      strings(row, "conditions").add(Json.string(rule.get("condition")));
      for (var finding : rows(analysis.get("findings")))
        if (engine.equals("webaudit")
            && rows(finding.get("rules")).stream().anyMatch(r -> id.equals(r.get("id"))))
          strings(row, "finding_ids").add((String) finding.get("id"));
      boolean isReady = ready.getOrDefault(id, true),
          partial = !Json.bool(report.get("complete")) || ob[0] < population;
      if (engine.equals("geoip")
          && analysis.get("geoip") != null
          && rows(Json.obj(analysis.get("geoip")).get("databases")).stream()
              .noneMatch(db -> "asn".equals(db.get("role")))) {
        isReady = false;
        strings(row, "limitations")
            .add("ASN database is unavailable; ASN similarity was not evaluated");
      }
      if (!isReady)
        strings(row, "limitations")
            .add("Insufficient baseline observations or peers for statistical evaluation");
      if (engine.equals("geoip") && analysis.get("geoip") == null) {
        row.put("status", "not_performed");
        row.put("evaluation", "not_performed");
        row.put("count_quality", "unavailable");
        row.put("eligible_requests", null);
        row.put("detections", null);
        strings(row, "limitations").add("GeoIP database not configured");
      } else status(row, Json.bool(rule.get("supported")), partial, isReady);
      if (ob[0] < population)
        strings(row, "limitations")
            .add("Some observations lack required fields or a known timezone");
      if (!signature)
        strings(row, "limitations")
            .add(
                "Distinct detected request count is unavailable until full evidence association;"
                    + " matched_candidates are filter/signature candidates, not confirmed attacks");
      out.add(row);
      byRule.put(key, row);
    }
    for (var aspect : ASPECTS) {
      String id = (String) aspect.get("id");
      var ids = ((List<?>) aspect.get("rules")).stream().map(Object::toString).toList();
      long[] ob = aspects.getOrDefault(id, new long[3]);
      var row =
          coverageRow(
              "ASPECT-" + id,
              (String) aspect.get("name"),
              ids,
              List.of(id.equals("multi_ip") ? "geoip" : "webaudit"),
              ob);
      boolean
          partial =
              !Json.bool(report.get("complete"))
                  || Json.bool(aspect.get("partial"))
                  || ob[0] < population,
          isReady = true;
      for (String ruleID : ids) {
        var rr = byRule.get(key(ruleID.equals("geoip-similarity") ? "geoip" : "webaudit", ruleID));
        if (rr == null) continue;
        row.put(
            "has_detections",
            Json.bool(row.get("has_detections")) || Json.bool(rr.get("has_detections")));
        for (String f : strings(rr, "finding_ids"))
          if (!strings(row, "finding_ids").contains(f)) strings(row, "finding_ids").add(f);
        strings(row, "conditions").addAll(strings(rr, "conditions"));
        if (ruleID.startsWith("WB-")
            || ruleID.startsWith("WS-")
            || ruleID.equals("geoip-similarity")) {
          row.put("detected_requests", null);
          row.put("detections", null);
          partial = true;
          if ("unable".equals(rr.get("evaluation"))) isReady = false;
        }
      }
      if (Json.bool(aspect.get("partial")))
        strings(row, "limitations")
            .add(
                "Related or shared rules cover only part of this perspective; separate labels do"
                    + " not imply independent detections");
      status(row, !ids.isEmpty(), partial, isReady);
      if (id.equals("multi_ip") && analysis.get("geoip") == null) {
        row.put("status", "not_performed");
        row.put("evaluation", "not_performed");
        row.put("complete", false);
        row.put("count_quality", "unavailable");
        for (String field : List.of("eligible_requests", "detected_requests", "detections"))
          row.put(field, null);
      }
      out.add(row);
    }
    out.sort(Comparator.comparing(r -> (String) r.get("id")));
    report.put("analysis_rules", rules);
    report.put("coverage", out);
    return out;
  }

  void write(BundleWriter writer, Map<String, Object> report) throws IOException {
    writer.csv(
        "analysis-rules.csv",
        List.of(
            "rule_id",
            "engine",
            "kind",
            "category",
            "severity",
            "description",
            "supported",
            "enabled",
            "required_fields",
            "conditions"),
        write -> {
          for (var row : rules)
            write.accept(
                Bundle.cell(row, "id"),
                Bundle.cell(row, "engine"),
                Bundle.cell(row, "kind"),
                Bundle.cell(row, "category"),
                Bundle.cell(row, "severity"),
                Bundle.cell(row, "description"),
                Bundle.cell(row, "supported"),
                Bundle.cell(row, "enabled"),
                Bundle.join(row.get("required_fields")),
                Bundle.cell(row, "condition"));
        });
    List<String> header =
        List.of(
            "coverage_id",
            "name",
            "description",
            "rule_ids",
            "engines",
            "status",
            "evaluation",
            "complete",
            "has_detections",
            "eligible_requests",
            "detected_requests",
            "related_requests",
            "detections",
            "matched_candidates",
            "finding_ids",
            "conditions",
            "limitations",
            "count_quality");
    writer.csv(
        "analysis-coverage.csv",
        header,
        write -> {
          for (var row : rows(report.get("coverage"))) {
            var cells = new ArrayList<String>();
            for (String field : header) {
              Object value = row.get(field.equals("coverage_id") ? "id" : field);
              cells.add(value instanceof Collection<?> ? Bundle.join(value) : Json.string(value));
            }
            write.accept(cells.toArray(String[]::new));
          }
        });
  }
}
