package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReportReadabilityTest {
  @TempDir Path dir;

  @Test
  void guidesReadersFromObservedEvidenceToRequestsAndResultReporting() throws Exception {
    Path input = dir.resolve("access.log");
    Files.writeString(input, BundleTest.LINE + "\n");
    for (String lang : List.of("ja", "en")) {
      var options = new BundleOptions();
      options.language = lang;
      Path out = dir.resolve(lang);
      var report = Bundle.generate(List.of(input), out, new Options(), options);
      String executive = Files.readString(out.resolve("executive-summary.html"));
      String technical = Files.readString(out.resolve("technical-report.html"));
      for (String id :
          List.of("quick-read", "quick-risk-list", "next-actions", "decision-conditions"))
        assertTrue(executive.contains("id=\"" + id + "\""), id);
      for (String id :
          List.of(
              "chapter-6",
              "investigation-workflow",
              "secondary-selection-summary",
              "all-investigation-targets",
              "result-reporting")) assertTrue(technical.contains("id=\"" + id + "\""), id);
      assertTrue(technical.contains("#request-"));
      if (lang.equals("en"))
        assertTrue(technical.contains("Source / group: 192.0.2.1 / 192.0.2.1"));
      assertTrue(technical.contains("href=\"#investigation-workflow\""));
      assertTrue(
          technical.indexOf("id=\"investigation-workflow\"")
              < technical.indexOf("id=\"appendix-assessment\""));
      assertTrue(
          technical.contains(
              new ReportLanguage(lang)
                  .text(
                      "Rule applicability and the actual outcome remain unassessed for this"
                          + " independent detection.")));
      assertFalse(Files.exists(out.resolve("report.html")));
      for (String name : List.of("suspicious-requests.csv", "related-requests.csv")) {
        String header = Files.readAllLines(out.resolve(name)).getFirst();
        assertTrue(header.startsWith("attack_categories,timestamp,source_ip,"), header);
        assertTrue(header.indexOf("request_id") > header.indexOf("raw_log"));
      }
      var decision = Json.obj(report.get("decision_support"));
      assertEquals("webaudit/response-rules-2", decision.get("version"));
      assertFalse(Json.string(decision.get("common_escalation_condition")).isEmpty());
      var profile =
          Json.rows(Json.object(Files.readString(out.resolve("risk-rules.json"))).get("profiles"))
              .getFirst();
      assertNotEquals(
          decision.get("common_escalation_condition"), profile.get("escalation_condition"));
      BundleAudienceTest.verifyBrowser(out);
    }
  }

  @Test
  void riskCorrespondenceUsesRecordedIdsAndExactEngineRatherThanTitle() {
    var report =
        BundleAudienceTest.model(
            true,
            1,
            List.of(
                Json.map(
                    "id", "native", "outcome", Json.map("missing", List.of("response content")))),
            List.of(Json.map("id", "source", "engine", "aura", "rule_id", "shared")));
    report.put(
        "decision_support",
        Json.map(
            "risks",
            List.of(
                Json.map(
                    "id",
                    "risk-a",
                    "case_id",
                    "native",
                    "kind",
                    "finding",
                    "title",
                    "Same",
                    "priority",
                    "high",
                    "outcome",
                    "unknown"),
                Json.map(
                    "id",
                    "risk-b",
                    "case_id",
                    "source",
                    "kind",
                    "independent_detection",
                    "title",
                    "Same",
                    "priority",
                    "unassessed",
                    "outcome",
                    "not_assessed")),
            "actions",
            List.of(Json.map("case_id", "native", "materials", List.of("application audit")))));
    var coverage =
        List.of(
            Json.map(
                "id", "ASPECT-native", "has_detections", true, "finding_ids", List.of("native")),
            Json.map(
                "id", "RULE-wrong", "engines", List.of("webaudit"), "rule_ids", List.of("shared")),
            Json.map(
                "id", "RULE-right", "engines", List.of("aura"), "rule_ids", List.of("shared")));
    var rows = BundleHTML.riskCoverage(report, coverage);
    assertEquals(2, rows.size());
    assertEquals("ASPECT-native", Json.rows(rows.get(0).get("perspectives")).getFirst().get("id"));
    assertEquals("RULE-right", Json.rows(rows.get(1).get("perspectives")).getFirst().get("id"));
    assertEquals(List.of("response content"), rows.get(0).get("missing"));
    assertEquals(List.of("application audit"), rows.get(0).get("materials"));
    assertEquals(List.of(), rows.get(1).get("missing"));
  }

  @Test
  void zeroParsedInputNeverClaimsNoSuspiciousActivity() throws Exception {
    Path input = dir.resolve("empty.log");
    Files.writeString(input, "");
    for (String lang : List.of("ja", "en")) {
      var options = new BundleOptions();
      options.language = lang;
      Path out = dir.resolve("empty-" + lang);
      Bundle.generate(List.of(input), out, new Options(), options);
      String page = Files.readString(out.resolve("executive-summary.html"));
      String quick = page.split("id=\"quick-read\"", 2)[1].split("</section>", 2)[0];
      assertTrue(
          quick.contains(lang.equals("ja") ? "何が起きたか判断できません" : "what happened cannot be assessed"));
      assertFalse(quick.contains("No suspicious candidates"));
    }
  }
}
