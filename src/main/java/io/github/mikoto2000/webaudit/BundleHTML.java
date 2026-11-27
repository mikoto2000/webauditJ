package io.github.mikoto2000.webaudit;

import freemarker.core.HTMLOutputFormat;
import freemarker.template.*;
import freemarker.template.utility.DeepUnwrap;
import java.io.*;
import java.util.*;

/** Read-only bounded presentation of the common model; no alternative analysis. */
final class BundleHTML {
  static final Configuration HTML = new Configuration(Configuration.VERSION_2_3_35);

  static {
    HTML.setClassLoaderForTemplateLoading(BundleHTML.class.getClassLoader(), "/");
    HTML.setDefaultEncoding("UTF-8");
    HTML.setOutputFormat(HTMLOutputFormat.INSTANCE);
    HTML.setAutoEscapingPolicy(Configuration.ENABLE_IF_SUPPORTED_AUTO_ESCAPING_POLICY);
    HTML.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
    HTML.setLogTemplateExceptions(false);
    HTML.setWrapUncheckedExceptions(true);
  }

  static final List<String> CHAPTERS =
      List.of(
          "1. Investigation overview",
          "2. Investigation scope",
          "3. Analysis methods",
          "4. Assessment criteria",
          "5. Overall access statistics",
          "6. Investigation coverage",
          "7. Suspicious activity list",
          "8. Detailed analysis",
          "9. Overall assessment",
          "10. Limitations",
          "11. Recommended actions");

  static Object safe(Object value) {
    if (value == null) return "";
    if (value instanceof Map<?, ?> map) {
      var out = new LinkedHashMap<String, Object>();
      map.forEach((key, item) -> out.put(key.toString(), safe(item)));
      return out;
    }
    if (value instanceof Collection<?> values)
      return values.stream().map(BundleHTML::safe).toList();
    return value;
  }

  static String anchor(String engine, String id) {
    return Bundle.id("rule-", engine + "|" + id);
  }

  static List<Map<String, Object>> limit(Object rows, int max) {
    var values = BundleCoverage.rows(rows);
    return values.subList(0, Math.min(max, values.size()));
  }

  static Map<String, Object> chart(
      String title, List<Map<String, Object>> bars, String annex, int total) {
    long max = bars.stream().mapToLong(r -> Json.number(r.get("count"))).max().orElse(1);
    return Json.map(
        "title",
        title,
        "rows",
        bars,
        "maximum",
        Math.max(1, max),
        "annex",
        annex,
        "total_rows",
        total);
  }

  static Map<String, Object> countsChart(
      String title, Map<String, Object> counts, String annex, ReportLanguage tr) {
    var bars = new ArrayList<Map<String, Object>>();
    counts.forEach((key, value) -> {
      String label = tr.text(key);
      if (key.contains(":")) {
        String[] parts = key.split(":", 2);
        label = parts[0] + " / " + tr.text(parts[1]);
      }
      bars.add(Json.map("label", label, "count", value));
    });
    bars.sort(
        Comparator.comparingLong((Map<String, Object> r) -> -Json.number(r.get("count")))
            .thenComparing(r -> (String) r.get("label")));
    return chart(title, bars.subList(0, Math.min(30, bars.size())), annex, bars.size());
  }

  static List<Map<String, Object>> riskCoverage(
      Map<String, Object> report, List<? extends Map<String, Object>> coverage) {
    var findings = new HashMap<Object, Map<String, Object>>();
    for (var f : BundleCoverage.rows(Json.obj(report.get("analysis")).get("findings")))
      findings.put(f.get("id"), f);
    var detections = new HashMap<Object, Map<String, Object>>();
    for (var d : BundleCoverage.rows(report.get("detections"))) detections.put(d.get("id"), d);
    var materials = new HashMap<Object, Object>();
    for (var a : BundleCoverage.rows(Json.obj(report.get("decision_support")).get("actions")))
      materials.put(a.get("case_id"), a.get("materials"));
    var result = new ArrayList<Map<String, Object>>();
    for (var risk : BundleAudience.executiveRisks(report)) {
      Object id = risk.get("case_id");
      var matches = new ArrayList<Map<String, Object>>();
      String engine = "";
      Object missing = List.of();
      if (risk.get("kind").equals("finding")) {
        engine = "webaudit";
        var f = findings.get(id);
        if (f != null) missing = Json.obj(f.get("outcome")).getOrDefault("missing", List.of());
        for (var row : coverage)
          if (Json.string(row.get("id")).startsWith("ASPECT-")
              && Json.bool(row.get("has_detections"))
              && BundleRequests.strings(row.get("finding_ids")).contains(id)) matches.add(row);
        if (matches.isEmpty())
          for (var row : coverage)
            if (Json.string(row.get("id")).startsWith("RULE-")
                && BundleRequests.strings(row.get("finding_ids")).contains(id)) matches.add(row);
      } else if (detections.containsKey(id)) {
        var d = detections.get(id);
        engine = Json.string(d.get("engine"));
        for (var row : coverage)
          if (Json.string(row.get("id")).startsWith("RULE-")
              && BundleRequests.strings(row.get("engines")).contains(engine)
              && BundleRequests.strings(row.get("rule_ids")).contains(d.get("rule_id")))
            matches.add(row);
      }
      result.add(
          Json.map(
              "risk",
              risk,
              "perspectives",
              matches,
              "engine",
              engine,
              "missing",
              missing,
              "materials",
              materials.getOrDefault(id, List.of())));
    }
    return result;
  }

  static Map<String, Object> view(Map<String, Object> report, ReportLanguage tr) {
    var model = new HashMap<String, Object>();
    var analysis = Json.obj(report.get("analysis"));
    var stats = Json.obj(report.get("statistics"));
    var metadata = Json.obj(report.get("metadata"));
    model.put("r", report);
    model.put("lang", metadata.get("language"));
    model.put(
        "title",
        Json.string(metadata.get("title")).isEmpty()
            ? tr.text("Access log investigation report")
            : metadata.get("title"));
    model.put("chapters", CHAPTERS);
    var findings = limit(analysis.get("findings"), 100);
    var rules = limit(report.get("analysis_rules"), 1000);
    var coverage = limit(report.get("coverage"), 1000);
    var risksByCase = new HashMap<Object, Map<String, Object>>();
    for (var risk : BundleCoverage.rows(Json.obj(report.get("decision_support")).get("risks")))
      risksByCase.put(risk.get("case_id"), risk);
    var recommendationsByTarget = new HashMap<Object, List<Map<String, Object>>>();
    for (var rec : BundleCoverage.rows(report.get("recommendations")))
      if ("investigation".equals(rec.get("type"))) {
        var ids = new LinkedHashSet<String>(BundleRequests.strings(rec.get("finding_ids")));
        ids.addAll(BundleRequests.strings(rec.get("detection_ids")));
        for (var id : ids)
          recommendationsByTarget.computeIfAbsent(id, k -> new ArrayList<>()).add(rec);
      }
    var cases = new ArrayList<Map<String, Object>>();
    var sources = new ArrayList<Map<String, Object>>();
    var metrics = new HashMap<String, Map<String, Object>>();
    var assessments = new HashMap<String, Map<String, Object>>();
    for (var row : BundleCoverage.rows(report.get("finding_observations")))
      metrics.put((String) row.get("finding_id"), row);
    for (var row : BundleCoverage.rows(report.get("assessments")))
      assessments.put((String) row.get("finding_id"), row);
    var caseIDs = new HashSet<String>();
    var sourceIDs = new HashSet<String>();
    var ruleIDs = new HashSet<String>();
    var coverageIDs = new HashSet<String>();
    for (var rule : rules)
      ruleIDs.add(anchor((String) rule.get("engine"), (String) rule.get("id")));
    for (var row : coverage) coverageIDs.add((String) row.get("id"));
    for (var f : findings) {
      String id = (String) f.get("id");
      caseIDs.add(id);
      var assessment = assessments.getOrDefault(id, Map.of());
      var samples = new ArrayList<Map<String, Object>>();
      var evidence = BundleCoverage.rows(f.get("evidence"));
      var refs = BundleCoverage.rows(assessment.get("evidence_refs"));
      for (int i = 0; i < evidence.size(); i++)
        samples.add(
            Json.map(
                "evidence",
                evidence.get(i),
                "reference",
                i < refs.size() ? refs.get(i) : Map.of()));
      var ids = BundleCoverage.rows(f.get("rules")).stream().map(r -> r.get("id")).toList();
      var matching =
          rules.stream()
              .filter(r -> r.get("engine").equals("webaudit") && ids.contains(r.get("id")))
              .toList();
      cases.add(
          Json.map(
              "risk",
              risksByCase.getOrDefault(id, Map.of()),
              "recommendations",
              recommendationsByTarget.getOrDefault(id, List.of()),
              "brief_samples",
              samples.subList(0, Math.min(3, samples.size())),
              "finding",
              f,
              "metrics",
              metrics.getOrDefault(id, Map.of()),
              "assessment",
              assessment,
              "samples",
              samples,
              "rules",
              matching));
    }
    long sourceTotal = 0;
    for (var d : BundleCoverage.rows(report.get("detections"))) {
      if (Set.of("webaudit", "geoip").contains(d.get("engine"))) continue;
      sourceTotal++;
      if (sources.size() >= 100) continue;
      sourceIDs.add((String) d.get("id"));
      var source = BundlePresentation.source(report, d);
      var samples = new ArrayList<Map<String, Object>>();
      var evidence = BundleCoverage.rows(source.get("evidence"));
      var refs = BundleCoverage.rows(d.get("sample_evidence_refs"));
      for (int i = 0; i < evidence.size(); i++)
        samples.add(
            Json.map(
                "sample", evidence.get(i), "reference", i < refs.size() ? refs.get(i) : Map.of()));
      var rule =
          rules.stream()
              .filter(r ->
                  r.get("engine").equals(d.get("engine")) && r.get("id").equals(d.get("rule_id")))
              .findFirst()
              .orElse(Map.of());
      var uris = BundleRequests.strings(d.get("uri_examples"));
      sources.add(
          Json.map(
              "detection",
              d,
              "source",
              source,
              "rule",
              rule,
              "samples",
              samples,
              "risk",
              risksByCase.getOrDefault(d.get("id"), Map.of()),
              "recommendations",
              recommendationsByTarget.getOrDefault(d.get("id"), List.of()),
              "brief_uris",
              uris.subList(0, Math.min(3, uris.size()))));
    }
    var charts = new ArrayList<Map<String, Object>>();
    var dimensions = Json.obj(stats.get("dimensions"));
    var names =
        Map.ofEntries(
            Map.entry("method", "HTTP methods"),
            Map.entry("status", "HTTP status codes"),
            Map.entry("status_class", "HTTP status classes"),
            Map.entry("ip", "Top source IPs"),
            Map.entry("host", "Target hosts"),
            Map.entry("uri", "Top URI paths"),
            Map.entry("user_agent", "User-Agents"),
            Map.entry("country", "Countries"),
            Map.entry("asn", "ASNs"));
    for (String dim :
        List.of(
            "method",
            "status",
            "status_class",
            "ip",
            "host",
            "uri",
            "user_agent",
            "country",
            "asn")) {
      var rows = BundleCoverage.rows(dimensions.get(dim));
      var bars = new ArrayList<Map<String, Object>>();
      for (var row : rows.subList(0, Math.min(20, rows.size()))) {
        String label =
            Json.bool(row.get("other"))
                ? tr.text("Other groups")
                : row.get("value") == null ? tr.text("unknown") : row.get("value").toString();
        bars.add(Json.map("label", label, "count", row.get("requests")));
      }
      if ((dim.equals("country") || dim.equals("asn")) && !Json.bool(stats.get("geoip_enabled")))
        continue;
      charts.add(
          chart(
              names.get(dim),
              bars,
              "statistics/" + dim.replace('_', '-') + "-summary.csv",
              rows.size()));
    }
    charts.add(
        countsChart(
            "Detection counts by engine and category",
            Json.obj(stats.get("attack_detections")),
            "analysis-coverage.csv",
            tr));
    charts.add(
        countsChart("Severity counts", Json.obj(analysis.get("severities")), "findings.csv", tr));
    charts.add(
        countsChart("Outcome counts", Json.obj(analysis.get("outcomes")), "findings.csv", tr));
    var timeline = limit(stats.get("timeline"), 120);
    long timelineMax =
        timeline.stream().mapToLong(row -> Json.number(row.get("requests"))).max().orElse(1);
    model.put("risk_coverage", riskCoverage(report, coverage));
    model.put(
        "detected_aspects",
        coverage.stream()
            .filter(c ->
                Json.string(c.get("id")).startsWith("ASPECT-")
                    && Json.bool(c.get("has_detections")))
            .toList());
    model.put(
        "incomplete_aspects",
        coverage.stream()
            .filter(c ->
                Json.string(c.get("id")).startsWith("ASPECT-") && !Json.bool(c.get("complete")))
            .toList());
    model.put("cases", cases);
    model.put("sources", sources);
    model.put("coverage", coverage);
    model.put("rules", rules);
    model.put("charts", charts);
    model.put("timeline", timeline);
    model.put("timeline_max", Math.max(1, timelineMax));
    model.put("inventory", limit(report.get("inventory"), 1000));
    model.put(
        "truncated_cases", BundleCoverage.rows(analysis.get("findings")).size() > cases.size());
    model.put("truncated_sources", sourceTotal > sources.size());
    model.put(
        "truncated_rules", BundleCoverage.rows(report.get("analysis_rules")).size() > rules.size());
    model.put(
        "truncated_coverage", BundleCoverage.rows(report.get("coverage")).size() > coverage.size());
    model.put("truncated_inventory", BundleCoverage.rows(report.get("inventory")).size() > 1000);
    model.put(
        "caseVisible",
        (TemplateMethodModelEx) args -> caseIDs.contains(args.getFirst().toString()));
    model.put(
        "sourceVisible",
        (TemplateMethodModelEx) args -> sourceIDs.contains(args.getFirst().toString()));
    model.put(
        "coverageVisible",
        (TemplateMethodModelEx) args -> coverageIDs.contains(args.getFirst().toString()));
    model.put(
        "ruleVisible",
        (TemplateMethodModelEx)
            args -> ruleIDs.contains(anchor(args.get(0).toString(), args.get(1).toString())));
    model.put(
        "ruleAnchor",
        (TemplateMethodModelEx) args -> anchor(args.get(0).toString(), args.get(1).toString()));
    return model;
  }

  static String string(Object model) throws TemplateModelException {
    if (model instanceof TemplateScalarModel s) return s.getAsString();
    if (model instanceof TemplateBooleanModel b) return Boolean.toString(b.getAsBoolean());
    if (model instanceof TemplateNumberModel n) return n.getAsNumber().toString();
    return model.toString();
  }

  static void write(Writer out, Map<String, Object> report) throws IOException {
    var tr = new ReportLanguage(Json.string(Json.obj(report.get("metadata")).get("language")));
    var model = view(report, tr);
    var safe = new HashMap<String, Object>();
    model.forEach((key, value) ->
        safe.put(key, value instanceof TemplateMethodModelEx ? value : safe(value)));
    safe.put("t", (TemplateMethodModelEx) args -> tr.text(string(args.getFirst())));
    safe.put("outcome", (TemplateMethodModelEx) args -> tr.outcome(string(args.getFirst())));
    safe.put("diagnostic", (TemplateMethodModelEx) args -> tr.diagnostic(string(args.getFirst())));
    safe.put(
        "n",
        (TemplateMethodModelEx)
            args -> {
              String value = string(args.getFirst());
              return value.isEmpty() ? tr.text("unknown") : value;
            });
    safe.put(
        "specified",
        (TemplateMethodModelEx)
            args -> {
              String value = string(args.getFirst());
              return value.isEmpty() ? tr.text("Not specified") : value;
            });
    safe.put(
        "j",
        (TemplateMethodModelEx)
            args ->
                Json.MAPPER
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(DeepUnwrap.unwrap((TemplateModel) args.getFirst())));
    safe.put("v", new HashMap<>(safe));
    safe.put(
        "entries",
        (TemplateMethodModelEx)
            a -> {
              Object value = DeepUnwrap.unwrap((TemplateModel) a.getFirst());
              return value instanceof Map<?, ?> ? value : Map.of();
            });
    safe.put(
        "items",
        (TemplateMethodModelEx)
            a -> BundleAudience.items(DeepUnwrap.unwrap((TemplateModel) a.getFirst())));
    safe.put("scalar", (TemplateMethodModelEx) a -> string(a.getFirst()));
    safe.put(
        "truth",
        (TemplateMethodModelEx)
            a -> BundleAudience.truth(DeepUnwrap.unwrap((TemplateModel) a.getFirst())));
    safe.put("dt", safe.get("n"));
    safe.put(
        "brief",
        (TemplateMethodModelEx)
            a -> {
              String value = string(a.getFirst());
              return value.codePointCount(0, value.length()) > 160
                  ? value.substring(0, value.offsetByCodePoints(0, 160)) + "…"
                  : value;
            });
    safe.put(
        "analysisStatus",
        (TemplateMethodModelEx)
            a ->
                tr.text(
                    switch (string(a.getFirst())) {
                      case "completed" -> "Completed analysis";
                      case "failed" -> "Failed analysis";
                      default -> "Partial analysis";
                    }));
    safe.put(
        "meanBytes",
        (TemplateMethodModelEx)
            a -> {
              var m = Json.obj(DeepUnwrap.unwrap((TemplateModel) a.getFirst()));
              return Json.number(m.get("bytes_count")) == 0
                  ? tr.text("unknown")
                  : ((Number) m.get("bytes_sum")).doubleValue() / Json.number(m.get("bytes_count"));
            });
    safe.put(
        "percent",
        (TemplateMethodModelEx)
            a -> {
              Object value = DeepUnwrap.unwrap((TemplateModel) a.getFirst());
              return value instanceof Number n
                  ? String.format(Locale.ROOT, "%.2f%%", n.doubleValue())
                  : tr.text("unknown");
            });
    var requestIDs = new HashSet<String>();
    for (var c : BundleCoverage.rows(Json.obj(report.get("secondary_investigation")).get("cases")))
      requestIDs.add(Json.string(c.get("id")));
    safe.put("requestable", (TemplateMethodModelEx) a -> requestIDs.contains(string(a.getFirst())));
    safe.put(
        "requestTargets",
        (TemplateMethodModelEx)
            a -> {
              var rec = Json.obj(DeepUnwrap.unwrap((TemplateModel) a.getFirst()));
              var ids = new LinkedHashSet<String>(BundleRequests.strings(rec.get("finding_ids")));
              ids.addAll(BundleRequests.strings(rec.get("detection_ids")));
              return ids.stream().filter(requestIDs::contains).toList();
            });
    try {
      HTML.getTemplate("investigation.ftlh").process(safe, out);
    } catch (TemplateException e) {
      throw new IOException("Investigation HTML report failed", e);
    }
  }
}
