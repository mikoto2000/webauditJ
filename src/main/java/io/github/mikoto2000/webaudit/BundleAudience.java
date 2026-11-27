package io.github.mikoto2000.webaudit;

import freemarker.template.*;
import freemarker.template.utility.DeepUnwrap;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Audience views of the masked common model; never reclassifies detection outcomes. */
final class BundleAudience {
  static final String RULES = "webaudit/response-rules-2",
      TEMPLATE = "webaudit/secondary-prompt-1",
      SPEC = "webaudit/report-spec-1";
  private final Map<String, Object> report, content, decision, plan;
  private final List<Map<String, Object>> risks = new ArrayList<>(),
      actions = new ArrayList<>(),
      cases = new ArrayList<>();
  private final String lang;

  BundleAudience(Map<String, Object> report) {
    this.report = report;
    lang = Json.string(Json.obj(report.get("metadata")).get("language"));
    content = Json.obj(Json.obj(Json.resource("audience-content.json")).get(lang));
    decision =
        Json.map(
            "version",
            RULES,
            "analysis_complete",
            report.get("complete"),
            "response_level",
            "monitor",
            "confirmed_impact",
            content.get("confirmed_impact"),
            "common_escalation_condition",
            content.get("common_escalation_condition"),
            "common_if_deferred",
            content.get("common_if_deferred"),
            "response_rules",
            content.get("response_rules"),
            "risks",
            risks,
            "actions",
            actions,
            "limitations",
            content.get("limitations"),
            "closure_conditions",
            content.get("closure_conditions"));
    plan =
        Json.map(
            "version",
            "webaudit/secondary-plan-1",
            "template_version",
            TEMPLATE,
            "risk_rules_version",
            RULES,
            "language",
            lang,
            "generation_only",
            true,
            "trust_boundary",
            content.get("trust_boundary"),
            "defaults",
            Json.map(
                "primary",
                "./primary-report",
                "additional",
                "./additional-logs",
                "output",
                "./secondary-report"),
            "prompt_prefix",
            content.get("secondaryPrefix"),
            "prompt_suffix",
            content.get("secondarySuffix"),
            "cases",
            cases);
  }

  static List<Map<String, Object>> rows(Object value) {
    return BundleCoverage.rows(value);
  }

  String t(String ja) {
    return Json.string(Json.obj(content.get("text")).getOrDefault(ja, ja));
  }

  void prepare() {
    var analysis = Json.obj(report.get("analysis"));
    var metrics = new HashMap<String, Map<String, Object>>();
    for (var m : rows(report.get("finding_observations")))
      metrics.put(Json.string(m.get("finding_id")), m);
    var refs = new HashMap<String, Object>();
    for (var a : rows(report.get("assessments")))
      refs.put(Json.string(a.get("finding_id")), a.get("evidence_refs"));
    for (var f : rows(analysis.get("findings"))) {
      String id = Json.string(f.get("id"));
      var m = metrics.getOrDefault(id, Map.of());
      var context =
          Json.map(
              "source_ip",
              f.get("ip"),
              "host",
              f.get("host"),
              "user_agent",
              f.get("user_agent"),
              "timezone_unknown",
              Json.bool(f.get("timezone_unknown")),
              "uris",
              m.get("uri_samples"),
              "status_counts",
              m.get("status_counts"),
              "categories",
              f.get("categories"));
      if (!Json.bool(f.get("timezone_unknown"))) {
        context.put("first", f.get("first"));
        context.put("last", f.get("last"));
      }
      add(
          id,
          "finding",
          BundlePresentation.priority(f),
          Json.string(Json.obj(f.get("outcome")).get("verdict")),
          Json.number(m.get("requests")),
          Json.string(report.get("count_quality")),
          BundleRequests.strings(f.get("categories")),
          context,
          refs.getOrDefault(id, List.of()));
    }
    for (var d : rows(report.get("detections"))) {
      if (Set.of("webaudit", "geoip").contains(d.get("engine"))) continue;
      add(
          Json.string(d.get("id")),
          "independent_detection",
          "unassessed",
          "unassessed",
          Json.number(d.get("request_count")) + Json.number(d.get("related_request_count")),
          Json.string(d.get("count_quality")),
          List.of(Json.string(d.get("category"))),
          Json.map(
              "source_ip",
              d.get("source_ip"),
              "host",
              d.get("host"),
              "first",
              d.get("first"),
              "last",
              d.get("last"),
              "uris",
              d.get("uri_examples"),
              "engine",
              d.get("engine"),
              "rule_id",
              d.get("rule_id"),
              "direct_observations",
              d.get("request_count"),
              "related_observations",
              d.get("related_request_count")),
          d.getOrDefault("evidence_refs", List.of()));
    }
    if (!decision.get("response_level").equals("priority")
        && (!Json.bool(report.get("complete"))
            || Json.number(Json.obj(report.get("summary")).get("parsed_lines")) == 0))
      decision.put("response_level", "hold");
    String level = Json.string(decision.get("response_level"));
    decision.put("response_label", Json.obj(content.get("labels")).get(level));
    decision.put("reason", Json.obj(content.get("reasons")).get(level));
    report.put("decision_support", decision);
    report.put("secondary_investigation", plan);
  }

  void add(
      String id,
      String kind,
      String priority,
      String outcome,
      long count,
      String quality,
      List<String> categories,
      Map<String, Object> context,
      Object evidence) {
    var profiles = rows(content.get("profiles"));
    var profile = profiles.getLast();
    for (var candidate : profiles)
      if (BundleRequests.strings(candidate.get("categories")).stream()
          .anyMatch(categories::contains)) {
        profile = candidate;
        break;
      }
    var tr = new ReportLanguage(lang);
    var materials = new LinkedHashSet<String>();
    String support = "", refute = "";
    for (var g : Investigations.forCategories(categories)) {
      for (String where : BundleRequests.strings(g.get("where_to_check")))
        materials.add(tr.text(where));
      if (support.isEmpty()) {
        support = tr.text(Json.string(g.get("success_evidence")));
        refute = tr.text(Json.string(g.get("failure_evidence")));
      }
    }
    String reason = t("既存ルールの優先度と成否に基づく調査順序。組織の影響度や成功確率ではない。");
    if (kind.equals("independent_detection")) reason = t("独立検出は適用性・成否・優先度を未評価。ルールと証拠を確認する。");
    if (outcome.equals("possible_success")) reason = t("成功の疑いを裏付ける既存の要求間変化があり、追加証拠の確認を優先する。");
    String riskID = Bundle.id("RISK-", id + "|" + profile.get("id"));
    risks.add(
        Json.map(
            "id",
            riskID,
            "case_id",
            id,
            "kind",
            kind,
            "profile",
            profile.get("id"),
            "title",
            profile.get("title"),
            "priority",
            priority,
            "priority_reason",
            reason,
            "outcome",
            outcome,
            "condition",
            profile.get("condition"),
            "conditional_impact",
            profile.get("conditional_impact"),
            "next_action",
            profile.get("next_action"),
            "escalation_condition",
            Json.string(profile.get("escalation_condition")).isEmpty()
                ? content.get("common_escalation_condition")
                : profile.get("escalation_condition"),
            "if_deferred",
            content.get("common_if_deferred")));
    actions.add(
        Json.map(
            "id",
            Bundle.id("ACT-", id),
            "case_id",
            id,
            "risk_id",
            riskID,
            "action",
            profile.get("next_action"),
            "suggested_timing",
            content.get("suggested_timing"),
            "suggested_owner",
            content.get("suggested_owner"),
            "materials",
            List.copyOf(materials),
            "completion_condition",
            content.get("completion_condition"),
            "status",
            "not_started"));
    // Only bundled guidance, generated identifiers and counts enter the task block.
    cases.add(
        Json.map(
            "id",
            id,
            "kind",
            kind,
            "title",
            profile.get("title"),
            "priority",
            priority,
            "primary_outcome",
            outcome,
            "observation_count",
            count,
            "count_quality",
            quality,
            "risk_id",
            riskID,
            "required_materials",
            List.copyOf(materials),
            "question",
            profile.get("next_action"),
            "support_condition",
            support,
            "refutation_condition",
            refute,
            "correlation_rule",
            content.get("correlation_rule"),
            "limitations",
            content.get("limitations"),
            "evidence_refs",
            evidence,
            "untrusted_observations",
            context,
            "prompt_section",
            String.format(
                Locale.ROOT,
                "- %s / %s / %s / %d (%s)\n  - %s\n  - %s\n  - %s\n  - %s\n",
                id,
                priority,
                profile.get("title"),
                count,
                quality,
                profile.get("next_action"),
                String.join("; ", materials),
                support,
                refute)));
    if (priority.equals("high") || outcome.equals("possible_success"))
      decision.put("response_level", "priority");
    else if (decision.get("response_level").equals("monitor"))
      decision.put("response_level", "planned");
  }

  static String resource(String name) throws IOException {
    try (var in = BundleAudience.class.getResourceAsStream("/" + name)) {
      if (in == null) throw new IOException("Missing audience resource " + name);
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  static String templateSource(String name) throws IOException {
    String source = resource(name).replaceFirst("^<#ftl[^>]*>\\s*", "");
    int start = source.indexOf("<!doctype html>");
    if (start <= 0) return source;
    return "<!doctype html>\n"
        + source.substring(0, start)
        + source.substring(start + "<!doctype html>".length());
  }

  static String scriptJSON(Object value) {
    return Json.MAPPER
        .writeValueAsString(value)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029");
  }

  static String pathsJSON(Object paths) {
    var p = Json.obj(paths);
    return "{\n  \"primary\": "
        + scriptJSON(p.get("primary"))
        + ",\n  \"additional\": "
        + scriptJSON(p.get("additional"))
        + ",\n  \"output\": "
        + scriptJSON(p.get("output"))
        + "\n}";
  }

  String prompt(List<String> ids) throws IOException {
    var wanted = new HashSet<>(ids);
    if (wanted.isEmpty()) throw new IOException("Select at least one case");
    var out =
        new StringBuilder(Json.string(plan.get("prompt_prefix")))
            .append("```json\n")
            .append(pathsJSON(plan.get("defaults")))
            .append("\n```\n\n");
    for (var c : cases) if (wanted.remove(c.get("id"))) out.append(c.get("prompt_section"));
    if (!wanted.isEmpty()) throw new IOException("Unknown case selection");
    return out.append(plan.get("prompt_suffix"))
        .append('\n')
        .append(TEMPLATE)
        .append(" / ")
        .append(plan.get("version"))
        .append(" / ")
        .append(RULES)
        .append('\n')
        .toString();
  }

  List<Map<String, Object>> executiveRisks() {
    return executiveRisks(report);
  }

  static List<Map<String, Object>> executiveRisks(Map<String, Object> report) {
    return rows(Json.obj(report.get("decision_support")).get("risks")).stream()
        .sorted(
            Comparator.comparingInt(r ->
                r.get("outcome").equals("possible_success")
                    ? 0
                    : switch (Json.string(r.get("priority"))) {
                      case "high" -> 1;
                      case "medium" -> 2;
                      case "low" -> 3;
                      default -> 4;
                    }))
        .limit(10)
        .toList();
  }

  static List<Map<String, Object>> riskSummary(List<Map<String, Object>> risks) {
    var seen = new HashSet<Object>();
    return risks.stream().filter(r -> seen.add(r.get("title"))).toList();
  }

  static List<Map<String, Object>> outcomeCounts(Map<String, Object> counts) {
    var order =
        new ArrayList<>(
            List.of(
                "confirmed_success",
                "possible_success",
                "unknown",
                "likely_failed",
                "confirmed_failure"));
    counts.keySet().stream().filter(k -> !order.contains(k)).sorted().forEach(order::add);
    return order.stream()
        .filter(counts::containsKey)
        .map(k -> (Map<String, Object>) Json.map("label", k, "count", counts.get(k)))
        .toList();
  }

  static List<Map<String, Object>> escalationGroups(Map<String, Object> decision) {
    var groups = new LinkedHashMap<String, Map<String, Object>>();
    for (var risk : rows(decision.get("risks"))) {
      String condition = Json.string(risk.get("escalation_condition"));
      if (condition.isEmpty() || condition.equals(decision.get("common_escalation_condition")))
        continue;
      var group =
          groups.computeIfAbsent(
              condition,
              k ->
                  Json.map(
                      "title",
                      risk.get("title"),
                      "condition",
                      k,
                      "targets",
                      new ArrayList<Map<String, Object>>()));
      rows(group.get("targets")).add(risk);
    }
    return List.copyOf(groups.values());
  }

  static Object items(Object value) {
    return value instanceof Collection<?> || value instanceof Map<?, ?> ? value : List.of();
  }

  static boolean truth(Object value) {
    return value instanceof Boolean b
        ? b
        : value instanceof Number n
            ? n.doubleValue() != 0
            : value instanceof Collection<?> c
                ? !c.isEmpty()
                : value instanceof Map<?, ?> m
                    ? !m.isEmpty()
                    : value != null && !value.toString().isEmpty();
  }

  static Object unwrap(Object o) throws TemplateModelException {
    return DeepUnwrap.unwrap((TemplateModel) o);
  }

  String render(String name, boolean executive) throws IOException {
    var view = new LinkedHashMap<>(report);
    var d = new LinkedHashMap<>(decision);
    var visible = executiveRisks();
    var ids = new HashSet<String>();
    visible.forEach(r -> ids.add(Json.string(r.get("id"))));
    if (executive) {
      d.put("risks", visible);
      var byCase = new HashMap<Object, Map<String, Object>>();
      actions.forEach(a -> byCase.put(a.get("case_id"), a));
      d.put(
          "actions",
          visible.stream()
              .map(r -> byCase.get(r.get("case_id")))
              .filter(Objects::nonNull)
              .toList());
    }
    view.put("decision_support", d);
    var model = new HashMap<String, Object>();
    model.put("r", BundleHTML.safe(view));
    model.put(
        "entries",
        (TemplateMethodModelEx)
            a -> {
              Object value = unwrap(a.getFirst());
              return value instanceof Map<?, ?> ? value : Map.of();
            });
    model.put("items", (TemplateMethodModelEx) a -> items(unwrap(a.getFirst())));
    var detailIDs = new HashSet<String>();
    rows(Json.obj(report.get("analysis")).get("findings")).stream()
        .limit(100)
        .forEach(f -> detailIDs.add(Json.string(f.get("id"))));
    rows(report.get("detections")).stream()
        .filter(f -> !Set.of("webaudit", "geoip").contains(f.get("engine")))
        .limit(100)
        .forEach(f -> detailIDs.add(Json.string(f.get("id"))));
    model.put(
        "caseDetailsAnchor",
        (TemplateMethodModelEx)
            a -> {
              String id = Json.string(unwrap(a.getFirst()));
              return detailIDs.contains(id) ? id : "";
            });
    model.put(
        "executiveVisible",
        (TemplateMethodModelEx) a -> ids.contains(Json.string(unwrap(a.getFirst()))));
    model.put("riskSummary", (TemplateMethodModelEx) a -> riskSummary(rows(unwrap(a.getFirst()))));
    model.put(
        "outcomeCounts",
        (TemplateMethodModelEx) a -> outcomeCounts(Json.obj(unwrap(a.getFirst()))));
    model.put(
        "escalationGroups",
        (TemplateMethodModelEx) a -> escalationGroups(Json.obj(unwrap(a.getFirst()))));

    model.put(
        "l", (TemplateMethodModelEx) a -> Json.string(unwrap(a.get(lang.equals("en") ? 1 : 0))));
    model.put(
        "label",
        (TemplateMethodModelEx)
            a -> {
              String code = Json.string(unwrap(a.getFirst()));
              var labels =
                  Map.of(
                      "high",
                      List.of("高", "High"),
                      "medium",
                      List.of("中", "Medium"),
                      "low",
                      List.of("低", "Low"),
                      "unassessed",
                      List.of("未評価", "Unassessed"),
                      "finding",
                      List.of("WebAudit事案", "WebAudit incident"),
                      "independent_detection",
                      List.of("独立エンジン検出", "Independent engine detection"),
                      "not_started",
                      List.of("未着手", "Not started"));
              return labels.containsKey(code)
                  ? labels.get(code).get(lang.equals("en") ? 1 : 0)
                  : new ReportLanguage(lang).outcome(code);
            });
    model.put(
        "riskAnchor",
        (TemplateMethodModelEx)
            a -> {
              String id = Json.string(unwrap(a.getFirst()));
              return ids.contains(id) ? id : "risk-overview";
            });
    model.put(
        "jsonData",
        (TemplateMethodModelEx)
            a ->
                Json.MAPPER
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(unwrap(a.getFirst())));
    model.put(
        "scalar",
        (TemplateMethodModelEx)
            a -> {
              Object value = unwrap(a.getFirst());
              return value instanceof Boolean ? value.toString() : Json.string(value);
            });
    model.put(
        "truth",
        (TemplateMethodModelEx)
            a -> {
              Object value = unwrap(a.getFirst());
              return value instanceof Boolean b
                  ? b
                  : value instanceof Number n
                      ? n.longValue() != 0
                      : value instanceof Collection<?> c
                          ? !c.isEmpty()
                          : value != null && !value.toString().isEmpty();
            });
    var out = new StringWriter();
    try {
      BundleHTML.HTML.getTemplate(name).process(model, out);
    } catch (TemplateException e) {
      throw new IOException("Audience report failed", e);
    }
    return out.toString();
  }

  void csv(
      BundleWriter w,
      String name,
      List<String> header,
      List<String> fields,
      List<Map<String, Object>> values)
      throws IOException {
    w.csv(
        name,
        header,
        write -> {
          for (var row : values) {
            var cells = new ArrayList<String>();
            for (String key : fields) {
              Object v = row.get(key);
              cells.add(v instanceof Collection<?> ? Bundle.join(v) : Json.string(v));
            }
            write.accept(cells.toArray(String[]::new));
          }
        });
  }

  void write(BundleWriter w) throws IOException {
    w.json("data/decision-support.json", decision);
    w.json("data/investigation-plan.json", plan);
    w.json(
        "data/analysis.json",
        Json.map(
            "schema",
            "webaudit/analysis-summary-1",
            "status",
            report.get("status"),
            "complete",
            report.get("complete"),
            "count_quality",
            report.get("count_quality"),
            "summary",
            report.get("summary"),
            "statistics",
            report.get("statistics"),
            "full_report",
            "../report.json"));
    w.json("data/findings.json", cases);
    w.json("data/risks.json", risks);
    w.json(
        "data/recommendations.json",
        Json.map("recommendations", report.get("recommendations"), "actions", actions));
    var evidence = new LinkedHashMap<String, Object>();
    cases.forEach(c -> evidence.put(Json.string(c.get("id")), c.get("evidence_refs")));
    w.json("evidence/source-references.json", evidence);
    w.json(
        "risk-rules.json",
        Json.map(
            "version",
            RULES,
            "response_rules",
            decision.get("response_rules"),
            "common_escalation_condition",
            decision.get("common_escalation_condition"),
            "common_if_deferred",
            decision.get("common_if_deferred"),
            "escalation_fallback",
            "Use common_escalation_condition when a profile has no specific criteria",
            "priority_rule",
            "possible_success or severity high/critical => high; medium => medium; otherwise low;"
                + " independent detections unassessed",
            "profiles",
            content.get("profiles"),
            "profile_precedence",
            "resource, authentication, processing, data, availability; otherwise review",
            "impact",
            "conditional; never organization-specific probability or verified harm"));
    csv(
        w,
        "risk-register.csv",
        List.of(
            "risk_id",
            "case_id",
            "kind",
            "profile",
            "title",
            "priority",
            "priority_reason",
            "outcome",
            "condition",
            "conditional_impact",
            "next_action",
            "escalation",
            "if_deferred"),
        List.of(
            "id",
            "case_id",
            "kind",
            "profile",
            "title",
            "priority",
            "priority_reason",
            "outcome",
            "condition",
            "conditional_impact",
            "next_action",
            "escalation_condition",
            "if_deferred"),
        risks);
    csv(
        w,
        "action-plan.csv",
        List.of(
            "action_id",
            "case_id",
            "risk_id",
            "action",
            "suggested_timing",
            "suggested_owner",
            "materials",
            "completion",
            "status"),
        List.of(
            "id",
            "case_id",
            "risk_id",
            "action",
            "suggested_timing",
            "suggested_owner",
            "materials",
            "completion_condition",
            "status"),
        actions);
    for (boolean high : List.of(false, true)) {
      var selected =
          cases.stream()
              .filter(c -> !high || c.get("priority").equals("high"))
              .map(c -> Json.string(c.get("id")))
              .toList();
      w.text(
          "prompts/secondary-investigation-" + (high ? "priority" : "all") + ".md",
          selected.isEmpty() ? t("対象事案なし。調査開始を依頼するプロンプトは生成しません。\n") : prompt(selected));
    }
    for (var c : cases)
      w.text("prompts/cases/" + c.get("id") + ".md", prompt(List.of(Json.string(c.get("id")))));
    w.text("secondary-plan.js", "window.WebAuditSecondaryPlan = " + scriptJSON(plan) + ";\n");
    for (var item :
        Map.of(
                "secondary-investigation.js",
                "secondary-investigation.js",
                "report-spec.md",
                "report-spec.md",
                "templates/executive-summary.html",
                "audience_executive.ftlh",
                "templates/technical-report.html",
                "investigation.ftlh",
                "templates/report.css",
                "audience.css",
                "report.css",
                "audience.css",
                "README.md",
                "audience-readme.md")
            .entrySet())
      w.text(
          item.getKey(),
          item.getKey().startsWith("templates/") && item.getKey().endsWith(".html")
              ? templateSource(item.getValue())
              : resource(item.getValue()));
    String exec = render("audience_executive.ftlh", true);
    w.text("executive-summary.html", exec);
    w.text("executive.html", exec);
    var technical = new StringWriter();
    BundleHTML.write(technical, report);
    String nav =
        "<p><a href=\"executive-summary.html\">"
            + (lang.equals("en")
                ? "Start with results and next steps (plain-language summary)"
                : "まず結果と次の対応を見る（やさしい要約）")
            + "</a> · <a href=\"technical-report.html#secondary-investigation\">"
            + (lang.equals("en") ? "Secondary prompt generator" : "二次調査プロンプト生成")
            + "</a></p>";
    String legacy =
        technical.toString().replace("<nav id=\"contents\">", nav + "<nav id=\"contents\">");
    legacy =
        legacy.replaceFirst(
            "</ol>",
            "<li><a href=\"technical-report.html#investigation-workflow\">"
                + (lang.equals("en")
                    ? "Investigation requests and result reporting (technical report)"
                    : "追加調査の依頼と結果報告（技術者向け）")
                + "</a></li></ol>");
    w.text("report.html", legacy);
    String enhanced =
        legacy
            .replace(
                "<section id=\"appendix-assessment\">",
                render("audience_technical.ftlh", false) + "<section id=\"appendix-assessment\">")
            .replace(
                "default-src 'none'; style-src", "default-src 'none'; script-src 'self'; style-src")
            .replace(
                "</body>",
                "<script src=\"secondary-plan.js\"></script><script"
                    + " src=\"secondary-investigation.js\"></script></body>");
    enhanced =
        enhanced.replaceFirst(
            "<li><a href=\"technical-report.html#investigation-workflow\">.*?</a></li>",
            "<li><a href=\"#investigation-workflow\">"
                + (lang.equals("en")
                    ? "6. Investigation requests and result reporting"
                    : "第6章 追加調査の依頼と結果報告")
                + "</a></li>");
    w.text("technical-report.html", enhanced);
    w.text("technical.html", enhanced);
    w.text("index.html", render("audience_index.ftlh", false));
  }
}
