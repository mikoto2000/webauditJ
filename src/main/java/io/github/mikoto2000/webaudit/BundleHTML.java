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
      if (d.get("engine").equals("webaudit")) continue;
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
      sources.add(Json.map("detection", d, "source", source, "rule", rule, "samples", samples));
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
    try {
      HTML.getTemplate("investigation.ftlh").process(safe, out);
    } catch (TemplateException e) {
      throw new IOException("Investigation HTML report failed", e);
    }
  }
}
