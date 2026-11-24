package io.github.mikoto2000.webaudit;

import java.io.*;
import java.util.*;

/** Shared facts, inferences and recommendations for HTML, JSON and CSV. */
final class BundlePresentation {
  static List<Map<String, Object>> rows(Object value) {
    return BundleCoverage.rows(value);
  }

  static List<String> strings(Object value) {
    return BundleRequests.strings(value);
  }

  static String priority(Map<String, Object> f) {
    String severity = Json.string(f.get("severity"));
    if (Set.of("critical", "high").contains(severity)
        || "possible_success".equals(Json.obj(f.get("outcome")).get("verdict"))) return "high";
    return severity.equals("medium") ? "medium" : "low";
  }

  static String impact(String category) {
    return switch (category) {
      case "sqli", "nosqli", "ldap_injection", "xpath_injection" ->
          "If an applicable injection vulnerability exists, unauthorized data access, modification"
              + " or authentication bypass may be possible. Vulnerability and impact are"
              + " unverified.";
      case "command_injection",
          "deserialization",
          "log4shell",
          "spring4shell",
          "struts_ognl",
          "shellshock" ->
          "If vulnerable code handles the request, unauthorized code execution may be possible."
              + " Execution and compromise are unverified.";
      case "xss" ->
          "If the input is rendered unsafely, browser script execution may be possible. Response"
              + " content and browser execution are unverified.";
      case "lfi_traversal", "rfi", "sensitive_file" ->
          "If sensitive resources are exposed or file inclusion is vulnerable, confidential file"
              + " disclosure or code loading may be possible. Returned content is unverified.";
      case "ssrf" ->
          "If server-side fetching is vulnerable, internal service access or unintended outbound"
              + " connections may be possible. Server-side activity is unverified.";
      case "auth", "login", "access_bypass" ->
          "If authentication or access controls are vulnerable, unauthorized account or resource"
              + " access may be possible. Authentication results are unverified.";
      case "rate", "burst", "WS-hour", "WS-ip", "WS-errors", "WS-size", "WS-url-size" ->
          "Traffic or response anomalies may affect availability or indicate unusual processing,"
              + " but authorized activity and normal routing are alternatives. Impact is"
              + " unverified.";
      default ->
          "Observed probes alone do not establish an exploitable vulnerability, attacker intent or"
              + " actual impact.";
    };
  }

  static String preventive(String category) {
    return switch (category) {
      case "sensitive_file", "lfi_traversal", "rfi" ->
          "Verify whether the referenced paths are intended to be public before reviewing exposure"
              + " and file access controls.";
      case "sqli", "nosqli", "ldap_injection", "xpath_injection" ->
          "Confirm whether the affected input reaches a database or interpreter before reviewing"
              + " parameterization and validation.";
      case "xss" ->
          "Confirm the affected rendering context before reviewing output encoding and content"
              + " handling.";
      case "command_injection",
          "deserialization",
          "log4shell",
          "spring4shell",
          "struts_ognl",
          "shellshock" ->
          "Identify the targeted functionality and component before reviewing applicable fixes and"
              + " execution isolation.";
      case "rate", "burst", "WS-hour", "WS-ip" ->
          "Evaluate authorized traffic and service capacity before considering rate limits or"
              + " traffic controls.";
      default -> "";
    };
  }

  static Map<String, Object> reference(Map<String, Object> report, String file, long line) {
    String fileID = "";
    for (var input : rows(report.get("inventory")))
      if (Objects.equals(input.get("path"), file)) {
        fileID = (String) input.get("id");
        break;
      }
    return Json.map(
        "request_id",
        Bundle.id("REQ-", fileID + "\0" + line),
        "source_file_id",
        fileID,
        "source_file",
        file,
        "source_line",
        line);
  }

  static Map<String, Object> source(Map<String, Object> report, Map<String, Object> d) {
    if (!(d.get("source_index") instanceof Number index)) return Map.of();
    String field =
        switch (Json.string(d.get("engine"))) {
          case "hub" -> "upstream_alerts";
          case "aura" -> "aura_matches";
          case "aura-analysis" -> "aura_analysis";
          default -> "";
        };
    var alerts = rows(Json.obj(report.get("analysis")).get(field));
    return index.intValue() >= 0 && index.intValue() < alerts.size()
        ? alerts.get(index.intValue())
        : Map.of();
  }

  static Map<String, Object> recommendation(
      String id,
      String type,
      String title,
      String reason,
      String priority,
      List<String> findings,
      List<String> detections) {
    return Json.map(
        "id",
        id,
        "type",
        type,
        "title",
        title,
        "reason",
        reason,
        "priority",
        priority,
        "finding_ids",
        findings,
        "detection_ids",
        detections,
        "where_to_check",
        List.of(),
        "method",
        "",
        "success_evidence",
        "",
        "failure_evidence",
        "",
        "first",
        null,
        "last",
        null,
        "source_ip",
        "",
        "host",
        null,
        "uri_samples",
        List.of());
  }

  static void context(Map<String, Object> rec, Map<String, Object> f, Map<String, Object> metrics) {
    rec.put("source_ip", f.get("ip"));
    rec.put("host", f.get("host"));
    rec.put("uri_samples", metrics.getOrDefault("uri_samples", List.of()));
    if (!Json.bool(f.get("timezone_unknown"))) {
      rec.put("first", f.get("first"));
      rec.put("last", f.get("last"));
    }
  }

  static void prepare(Map<String, Object> report, int max) {
    var analysis = Json.obj(report.get("analysis"));
    var stats = Json.obj(report.get("statistics"));
    var evidence = Json.obj(report.get("evidence"));
    var language =
        new ReportLanguage(Json.string(Json.obj(report.get("metadata")).get("language")));
    var engineCounts = new TreeMap<String, Long>();
    for (var row : rows(report.get("coverage")))
      if (Json.string(row.get("id")).startsWith("RULE-")
          && strings(row.get("engines")).size() == 1
          && !strings(row.get("engines")).getFirst().equals("geoip")
          && row.get("detections") != null)
        engineCounts.merge(
            strings(row.get("engines")).getFirst(), Json.number(row.get("detections")), Long::sum);
    long totalLines = 0, parsed = 0, unparsed = 0, excluded = 0;
    for (var row : rows(report.get("inventory"))) {
      totalLines += Json.number(row.get("total_lines"));
      parsed += Json.number(row.get("parsed"));
      unparsed += Json.number(row.get("unparsed"));
      excluded += Json.number(row.get("excluded"));
    }
    var summary =
        Json.map(
            "input_files",
            rows(report.get("inventory")).size(),
            "total_lines",
            totalLines,
            "parsed_lines",
            parsed,
            "unparsed_lines",
            unparsed,
            "excluded_lines",
            excluded,
            "total_requests",
            stats.get("total_requests"),
            "unique_ips",
            stats.get("unique_ips"),
            "suspicious_requests",
            evidence.get("suspicious_requests"),
            "suspicious_ips",
            stats.get("suspicious_ips"),
            "suspicious_percent",
            stats.get("suspicious_percent"),
            "detections",
            engineCounts.values().stream().mapToLong(Long::longValue).sum(),
            "detections_by_engine",
            engineCounts,
            "findings",
            rows(analysis.get("findings")).size(),
            "priority_findings",
            0L,
            "severity_counts",
            analysis.get("severities"),
            "outcome_counts",
            analysis.get("outcomes"),
            "count_quality",
            report.get("count_quality"));
    report.put("summary", summary);
    var assessments = new ArrayList<Map<String, Object>>();
    var recs = new ArrayList<Map<String, Object>>();
    var metrics = new HashMap<String, Map<String, Object>>();
    for (var m : rows(report.get("finding_observations")))
      metrics.put((String) m.get("finding_id"), m);
    for (var f : rows(analysis.get("findings"))) {
      String fid = (String) f.get("id"), priority = priority(f);
      if (priority.equals("high"))
        summary.put("priority_findings", Json.number(summary.get("priority_findings")) + 1);
      var outcome = Json.obj(f.get("outcome"));
      var inferences = new LinkedHashSet<String>(strings(f.get("reasons")));
      for (var rule : rows(f.get("rules"))) inferences.add(Json.string(rule.get("description")));
      var impacts = new LinkedHashSet<String>();
      for (String category : strings(f.get("categories"))) impacts.add(impact(category));
      var coverage = new ArrayList<String>();
      for (var row : rows(report.get("coverage")))
        if (strings(row.get("finding_ids")).contains(fid)) coverage.add((String) row.get("id"));
      var related = new LinkedHashSet<String>();
      var ips = new LinkedHashSet<String>();
      if (analysis.get("geoip") != null)
        for (var hint : rows(Json.obj(analysis.get("geoip")).get("correlations")))
          if (strings(hint.get("incident_ids")).contains(fid)) {
            related.addAll(strings(hint.get("incident_ids")));
            ips.addAll(strings(hint.get("ips")));
          }
      related.remove(fid);
      ips.remove(Json.string(f.get("ip")));
      var refs = new ArrayList<Map<String, Object>>();
      for (var sample : rows(f.get("evidence"))) {
        var event = Json.obj(sample.get("event"));
        refs.add(reference(report, Json.string(event.get("file")), Json.number(event.get("line"))));
      }
      assessments.add(
          Json.map(
              "finding_id",
              fid,
              "detection_confidence",
              "unknown",
              "priority",
              priority,
              "facts",
              List.of(
                  "Counts, status codes and source references describe observed log records, not"
                      + " verified server-side execution."),
              "inferences",
              List.copyOf(inferences),
              "unknowns",
              outcome.get("missing"),
              "benign_alternatives",
              List.of(
                  "Authorized testing, legitimate traffic, shared addresses and common error"
                      + " routing may explain some matches. Validate application context."),
              "conditional_impacts",
              List.copyOf(impacts),
              "related_finding_ids",
              List.copyOf(related),
              "related_ips",
              List.copyOf(ips),
              "coverage_ids",
              coverage,
              "evidence_refs",
              refs));
      var guides = rows(outcome.get("investigation"));
      if (guides.isEmpty()) guides = Investigations.forCategories(strings(f.get("categories")));
      var preventive = new HashSet<String>();
      for (var guide : guides) {
        String category = (String) guide.get("category");
        var rec =
            recommendation(
                Bundle.id("REC-", fid + "\0" + category),
                "investigation",
                language.text("Collect corroborating evidence") + ": " + language.text(category),
                language.text(Json.string(guide.get("why_unknown"))),
                priority,
                List.of(fid),
                List.of());
        rec.put(
            "where_to_check",
            strings(guide.get("where_to_check")).stream().map(language::text).toList());
        rec.put(
            "method",
            language.text(
                "Correlate the recorded interval, host, URI and request identifiers; source IP"
                    + " alone is not verified identity."));
        rec.put("success_evidence", language.text(Json.string(guide.get("success_evidence"))));
        rec.put("failure_evidence", language.text(Json.string(guide.get("failure_evidence"))));
        context(rec, f, metrics.getOrDefault(fid, Map.of()));
        add(recs, rec, max, report);
        String advice = preventive(category);
        if (!advice.isEmpty() && preventive.add(advice)) {
          var prevention =
              recommendation(
                  Bundle.id("REC-", fid + "\0prevent\0" + advice),
                  "preventive_review",
                  language.text("Review applicable preventive controls"),
                  language.text(category),
                  priority,
                  List.of(fid),
                  List.of());
          prevention.put(
              "where_to_check",
              List.of(
                  language.text(
                      "The referenced route, component configuration and authorized traffic"
                          + " baseline")));
          prevention.put("method", language.text(advice));
          context(prevention, f, metrics.getOrDefault(fid, Map.of()));
          add(recs, prevention, max, report);
        }
      }
    }
    for (var d : rows(report.get("detections"))) {
      var source = source(report, d);
      var refs = new ArrayList<Map<String, Object>>();
      for (var sample : rows(source.get("evidence")))
        refs.add(
            reference(report, Json.string(sample.get("file")), Json.number(sample.get("line"))));
      d.put("sample_evidence_refs", refs);
      var events = new ArrayList<Map<String, Object>>();
      for (var event : rows(source.get("events"))) {
        if (events.size() >= 8) break;
        events.add(
            reference(report, Json.string(event.get("file")), Json.number(event.get("line"))));
      }
      d.put("evidence_refs", events);
      if (d.get("engine").equals("webaudit")) continue;
      var rec =
          recommendation(
              Bundle.id("REC-", Json.string(d.get("id"))),
              "investigation",
              language.text("Review independent source detection"),
              language.text(Json.string(d.get("reason"))),
              "unassessed",
              List.of(),
              List.of((String) d.get("id")));
      rec.put(
          "where_to_check",
          List.of(
              language.text("Original source references and the source rule conditions"),
              language.text("Application and server records for the recorded group and interval")));
      rec.put(
          "method",
          language.text(
              "Validate whether the rule applies to the target system; group membership is not"
                  + " proof that every request is malicious."));
      rec.put(
          "success_evidence",
          language.text(
              "Corroborating application, host or response evidence is required to confirm"
                  + " success."));
      rec.put(
          "failure_evidence",
          language.text(
              "Contemporaneous records showing rejection before the affected operation can support"
                  + " failure for the verified requests."));
      rec.put("first", d.get("first"));
      rec.put("last", d.get("last"));
      rec.put("source_ip", d.get("source_ip"));
      rec.put("host", d.get("host"));
      add(recs, rec, max, report);
    }
    boolean truncated = Json.bool(report.get("recommendations_truncated"));
    if (truncated) {
      report.put("complete", false);
      if (!report.get("status").equals("failed")) report.put("status", "partial");
      analysis.put("partial", true);
      Engine.warn(analysis, "Recommendation limit reached; recommendations are incomplete");
    }
    report.put("assessments", assessments);
    report.put("recommendations", recs);
    report.put("recommendations_truncated", truncated);
    report.put(
        "masking_enabled",
        !Json.bool(Json.obj(report.get("metadata")).get("include_sensitive_evidence")));
    report.put(
        "masking_notes",
        List.of(
            "Control characters in source values are displayed as escapes; originals are"
                + " unchanged.",
            "Deterministic masking covers common query credentials, Authorization and Cookie"
                + " values; it is not a guarantee that all personal or secret data is removed.",
            "Original files are unchanged. File identifiers, original hashes and line numbers"
                + " retain source traceability.",
            "IP addresses and investigator metadata are not anonymized; review sensitive evidence"
                + " before sharing."));
  }

  static void add(
      List<Map<String, Object>> recs,
      Map<String, Object> rec,
      int max,
      Map<String, Object> report) {
    if (recs.size() < max) recs.add(rec);
    else report.put("recommendations_truncated", true);
  }

  static void recommendations(BundleWriter writer, Map<String, Object> report) throws IOException {
    var header =
        List.of(
            "recommendation_id",
            "type",
            "title",
            "reason",
            "finding_ids",
            "detection_ids",
            "priority",
            "where_to_check",
            "method",
            "success_evidence",
            "failure_evidence",
            "first",
            "last",
            "source_ip",
            "host",
            "uri_samples");
    writer.csv(
        "recommendations.csv",
        header,
        write -> {
          for (var rec : rows(report.get("recommendations"))) {
            var cells = new ArrayList<String>();
            for (String field : header) {
              Object value = rec.get(field.equals("recommendation_id") ? "id" : field);
              cells.add(value instanceof Collection<?> ? Bundle.join(value) : Json.string(value));
            }
            write.accept(cells.toArray(String[]::new));
          }
        });
  }
}
