package io.github.mikoto2000.webaudit;

import freemarker.core.HTMLOutputFormat;
import freemarker.template.*;
import java.io.*;
import java.util.*;
import java.util.Map;
import org.apache.commons.csv.*;

final class Reports {
  private Reports() {}

  private static final Configuration HTML = new Configuration(Configuration.VERSION_2_3_35);

  static {
    HTML.setClassLoaderForTemplateLoading(Reports.class.getClassLoader(), "/");
    HTML.setDefaultEncoding("UTF-8");
    HTML.setOutputFormat(HTMLOutputFormat.INSTANCE);
    HTML.setAutoEscapingPolicy(Configuration.ENABLE_IF_SUPPORTED_AUTO_ESCAPING_POLICY);
    HTML.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
    HTML.setLogTemplateExceptions(false);
    HTML.setWrapUncheckedExceptions(true);
  }

  static void write(Writer out, Map<String, Object> report, String format) throws IOException {
    write(out, report, format, "ja");
  }

  static void write(Writer out, Map<String, Object> report, String format, String language)
      throws IOException {
    if (!Set.of("ja", "en").contains(language)) throw new IOException("--lang must be ja or en");
    switch (format) {
      case "json" -> {
        try {
          out.write(Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(report));
          out.write('\n');
        } catch (RuntimeException ex) {
          throw new IOException("JSON report failed", ex);
        }
      }
      case "html" -> {
        var model = new HashMap<String, Object>(report);
        var translator = new ReportLanguage(language);
        model.put("lang", language);
        model.put("t", (TemplateMethodModelEx) args -> translator.text(args.getFirst().toString()));
        model.put(
            "diagnostic",
            (TemplateMethodModelEx) args -> translator.diagnostic(args.getFirst().toString()));
        model.put(
            "outcome",
            (TemplateMethodModelEx) args -> translator.outcome(args.getFirst().toString()));
        model.put(
            "json_report", Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(report));
        try {
          HTML.getTemplate("report.ftlh").process(model, out);
        } catch (TemplateException ex) {
          throw new IOException("HTML report failed", ex);
        }
      }
      case "csv" -> csv(out, report);
      case "summary" -> summary(out, report);
      default -> throw new IOException("unsupported report format " + format);
    }
  }

  static String terminal(String text) {
    var out = new StringBuilder();
    text.codePoints()
        .forEach(cp ->
            out.appendCodePoint(
                Character.getType(cp) == Character.CONTROL
                        || cp == 0x202e
                        || cp == 0x202d
                        || cp >= 0x2066 && cp <= 0x2069
                    ? 0xfffd
                    : cp));
    return out.toString();
  }

  static String csvSafe(String s) {
    int i = 0;
    while (i < s.length()) {
      int cp = s.codePointAt(i);
      if (!Core.space(cp)) break;
      i += Character.charCount(cp);
    }
    if (i < s.length() && "=+-@".indexOf(s.charAt(i)) >= 0
        || !s.isEmpty() && "\t\r\n".indexOf(s.charAt(0)) >= 0) return "'" + s;
    return s;
  }

  private static List<Map<String, Object>> rows(Object value) {
    return value == null ? List.of() : Json.rows(value);
  }

  private static void record(CSVPrinter printer, String... cells) throws IOException {
    printer.printRecord(Arrays.stream(cells).map(Reports::csvSafe).toList());
  }

  private static void csv(Writer out, Map<String, Object> r) throws IOException {
    var printer = new CSVPrinter(out, CSVFormat.DEFAULT.builder().setRecordSeparator("\n").get());
    record(
        printer,
        "record_type",
        "id",
        "severity",
        "verdict",
        "ip",
        "observations",
        "reasons",
        "evidence_json",
        "details_json");
    var meta = new LinkedHashMap<>(r);
    for (String key : List.of("findings", "upstream_alerts", "aura_matches", "aura_analysis"))
      meta.put(key, null);
    record(printer, "metadata", "", "", "", "", "", "", "", Json.MAPPER.writeValueAsString(meta));
    for (var f : rows(r.get("findings")))
      record(
          printer,
          "incident",
          Json.string(f.get("id")),
          Json.string(f.get("severity")),
          Json.string(Json.obj(f.get("outcome")).get("verdict")),
          Json.string(f.get("ip")),
          Json.string(f.get("count")),
          String.join(
              "; ",
              ((List<?>) Json.obj(f.get("outcome")).get("reasons"))
                  .stream().map(Object::toString).toList()),
          Json.MAPPER.writeValueAsString(f.get("evidence")),
          Json.MAPPER.writeValueAsString(f));
    for (String key : List.of("upstream_alerts", "aura_matches", "aura_analysis"))
      for (var a : rows(r.get(key)))
        record(
            printer,
            Json.string(a.get("source")),
            Json.string(a.get("rule_id")),
            "",
            "unknown",
            Json.string(a.get("ip")),
            Json.string(a.get("count")),
            "Source detection; outcome not established",
            "",
            Json.MAPPER.writeValueAsString(a));
    printer.flush();
  }

  private static void line(Writer out, String text) throws IOException {
    out.write(text);
    out.write('\n');
  }

  private static void summary(Writer out, Map<String, Object> r) throws IOException {
    String state =
        Json.bool(r.get("partial")) ? "partial (coverage limits or input errors)" : "completed";
    line(
        out,
        "WebAuditJ "
            + r.get("version")
            + " - Analysis "
            + state
            + "\n\nAnalyzed:\n  Files: "
            + rows(r.get("files")).size()
            + "\n  Requests: "
            + r.get("requests")
            + "\n  Unparsed: "
            + r.get("unparsed")
            + "\n  Duplicate observations excluded: "
            + r.get("duplicates"));
    if (r.get("first") != null && r.get("last") != null)
      line(out, "  Period: " + r.get("first") + " .. " + r.get("last"));
    var findings = rows(r.get("findings"));
    line(out, "\nFindings: " + findings.size());
    for (String verdict :
        List.of(
            "confirmed_success",
            "possible_success",
            "unknown",
            "likely_failed",
            "confirmed_failure"))
      line(
          out,
          String.format(
              Locale.ROOT,
              "  %-20s %d",
              verdict,
              Json.number(Json.obj(r.get("outcomes")).get(verdict))));
    line(out, "\nTop findings:");
    if (findings.isEmpty())
      line(out, "  No WebAudit incidents; review upstream detections and coverage below.");
    for (var f : findings.stream().limit(5).toList()) {
      var rules = rows(f.get("rules"));
      String description =
          rules.isEmpty() ? "Review candidate" : Json.string(rules.getFirst().get("description"));
      line(
          out,
          String.format(
              Locale.ROOT,
              "  %-8s %s | %s | %s | %d observations",
              Json.string(f.get("severity")).toUpperCase(Locale.ROOT),
              terminal(description),
              terminal(Json.string(f.get("ip"))),
              Json.obj(f.get("outcome")).get("verdict"),
              Json.number(f.get("count"))));
      for (var g : rows(Json.obj(f.get("outcome")).get("investigation"))) {
        line(out, "    成否不明・成否確認の案内 [" + terminal(Json.string(g.get("category"))) + "]");
        line(out, "      不明な理由: " + terminal(Json.string(g.get("why_unknown"))));
        line(
            out,
            "      確認する場所: "
                + terminal(
                    String.join(
                        "; ",
                        ((List<?>) g.get("where_to_check"))
                            .stream().map(Object::toString).toList())));
        line(out, "      何が見つかれば判断できるか（成功）: " + terminal(Json.string(g.get("success_evidence"))));
        line(out, "      何が見つかれば判断できるか（失敗）: " + terminal(Json.string(g.get("failure_evidence"))));
      }
    }
    line(
        out,
        "\nUpstream detections:\n  Hub alerts: "
            + rows(r.get("upstream_alerts")).size()
            + "\n  Aura signature groups: "
            + rows(r.get("aura_matches")).size()
            + "\n  Aura analysis findings: "
            + rows(r.get("aura_analysis")).size());
    for (var a : rows(r.get("upstream_alerts")).stream().limit(5).toList())
      line(
          out,
          "  "
              + terminal(Json.string(a.get("rule_id")))
              + " | "
              + terminal(Json.string(a.get("ip")))
              + " | "
              + a.get("count")
              + " events");
    if (r.get("geoip") != null) {
      var g = Json.obj(r.get("geoip"));
      line(out, "\nGeoIP / ASN (investigation context):");
      for (var d : rows(g.get("databases")))
        line(
            out,
            "  "
                + terminal(Json.string(d.get("provider")))
                + " | "
                + terminal(Json.string(d.get("file")))
                + " | "
                + terminal(Json.string(d.get("type")))
                + " | version "
                + Objects.toString(d.get("version"), "unknown")
                + " | build "
                + Objects.toString(d.get("build_time"), "unknown")
                + " | retrieved "
                + Objects.toString(d.get("downloaded_at"), "unknown")
                + " | "
                + terminal(Json.string(d.get("license"))));
      line(out, "  " + g.get("context"));
      for (String set : List.of("countries", "asns"))
        for (var group : rows(g.get(set)).stream().limit(5).toList())
          line(
              out,
              "  "
                  + set
                  + " "
                  + terminal(Json.string(group.get("key")))
                  + " ("
                  + terminal(Json.string(group.get("name")))
                  + "): "
                  + group.get("requests")
                  + " requests, "
                  + group.get("ip_count")
                  + " IPs, "
                  + group.get("incidents")
                  + " incidents, "
                  + group.get("suspicious_ip_count")
                  + " suspicious IPs; "
                  + group.get("multiple_suspicious_ips"));
      for (var p : rows(g.get("peers")).stream().limit(5).toList()) {
        var info = Json.obj(p.get("info"));
        line(
            out,
            "  Peer "
                + terminal(Json.string(p.get("ip")))
                + ": "
                + info.get("classification")
                + " | "
                + info.get("status")
                + " | country "
                + info.get("country_status")
                + " | ASN "
                + info.get("asn_status"));
      }
      for (var c : rows(g.get("correlations")).stream().limit(5).toList())
        line(
            out,
            "  Similarity: ASN "
                + c.get("asn")
                + " | "
                + terminal(Json.string(c.get("path")))
                + " | "
                + c.get("category")
                + " | "
                + c.get("window_start")
                + " | "
                + c.get("ip_count")
                + " IPs (investigation hint)");
    }
    line(out, "\nWarnings:");
    for (Object warning : (List<?>) r.get("warnings"))
      line(out, "  " + terminal(warning.toString()));
  }
}
