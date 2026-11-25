package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.IntStream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class ReportLanguageTest {
  @TempDir Path dir;

  @Test
  void catalogCoversTemplateRulesAndEnglishInvestigation() throws Exception {
    var ja = Json.obj(Json.resource("locales/ja.json"));
    String template;
    try (var in = Reports.class.getResourceAsStream("/report.ftlh")) {
      template = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
    }
    var keys = Pattern.compile("\\$\\{t\\(\"([^\"]*)\"\\)").matcher(template);
    while (keys.find()) assertTrue(ja.containsKey(keys.group(1)), keys.group(1));
    String visible = template.replaceAll("(?s)<style>.*?</style>|\\$\\{.*?}|<[^>]*>", "");
    assertFalse(Pattern.compile("[A-Za-z]").matcher(visible).find(), visible);
    for (var rule : Json.rows(Json.resource("rules.json"))) {
      assertTrue(ja.containsKey(rule.get("description")), rule.toString());
      assertTrue(ja.containsKey(rule.get("category")), rule.toString());
    }
    var en = new ReportLanguage("en");
    for (var guide : Json.rows(Json.resource("investigation-golden.json"))) {
      var values =
          new ArrayList<>(
              List.of(
                  guide.get("why_unknown"),
                  guide.get("success_evidence"),
                  guide.get("failure_evidence")));
      values.addAll((List<?>) guide.get("where_to_check"));
      for (Object text : values)
        assertFalse(
            Pattern.compile("\\p{IsHan}").matcher(en.text(text.toString())).find(),
            text.toString());
    }
  }

  @Test
  void diagnosticsTranslateKnownPartsAndKeepExternalDetails() {
    var ja = new ReportLanguage("ja");
    var en = new ReportLanguage("en");
    for (var pair :
        List.of(
            List.of(
                "C:\\logs\\a.log:3: duplicate JSON field host",
                "C:\\logs\\a.log:3: 重複したJSONフィールド: host"),
            List.of("GeoIP asn lookup failed: bad metadata", "GeoIP ASNの検索に失敗"),
            List.of("directory C:\\logs: Access denied", "ディレクトリ C:\\logsの読み込みエラー"),
            List.of("open C:\\logs: Access denied", "診断情報（原文）: open C:\\logs: Access denied"))) {
      assertTrue(ja.diagnostic(pair.get(0)).contains(pair.get(1)));
      assertEquals(pair.get(0), en.diagnostic(pair.get(0)));
    }
  }

  @Test
  void concurrentRendersDoNotLeakLanguageOrMutateMachineReports() throws Exception {
    Path input = dir.resolve("sample.log");
    Files.writeString(input, CorrelatorTest.event(0, 404).raw);
    var r = Engine.analyze(List.of(input), new Options());
    String before = Json.MAPPER.writeValueAsString(r);
    IntStream.range(0, 12)
        .parallel()
        .forEach(i -> {
          String lang = i % 2 == 0 ? "ja" : "en";
          var out = new StringWriter();
          try {
            Reports.write(out, r, "html", lang);
          } catch (IOException ex) {
            throw new UncheckedIOException(ex);
          }
          assertTrue(out.toString().contains("lang=\"" + lang + "\""));
          assertEquals(lang.equals("ja"), out.toString().contains("成否を確認するには"));
        });
    assertEquals(before, Json.MAPPER.writeValueAsString(r));
    for (String format : List.of("json", "csv", "summary")) {
      var ja = new StringWriter();
      var en = new StringWriter();
      Reports.write(ja, r, format, "ja");
      Reports.write(en, r, format, "en");
      assertEquals(ja.toString(), en.toString(), format);
    }
    var out = new StringWriter();
    assertThrows(IOException.class, () -> Reports.write(out, r, "html", "fr"));
    assertEquals("", out.toString());
  }

  @Test
  void overviewAndConfidenceExplainIndependentDetectionsInBothLanguages() throws Exception {
    Path input = dir.resolve("overview.log");
    Files.writeString(input, CorrelatorTest.event(0, 404).raw);
    var report = Engine.analyze(List.of(input), new Options());
    var finding = Json.rows(report.get("findings")).getFirst();
    finding.remove("first");
    finding.remove("last");
    finding.put("timezone_unknown", true);
    for (boolean partial : List.of(false, true)) {
      report.put("partial", partial);
      for (String lang : List.of("ja", "en")) {
        var out = new StringWriter();
        Reports.write(out, report, "html", lang);
        String html = out.toString();
        var tr = new ReportLanguage(lang);
        for (String key :
            List.of(
                "Hub alerts:",
                "Aura signature groups:",
                "Aura analysis findings:",
                "How to read the indicators",
                "Evidence-strength indicator. This is not the probability of success.",
                "Wall clock; timezone unknown; cannot convert to UTC")) {
          assertTrue(html.contains(tr.text(key)), key);
        }
        assertTrue(html.contains("href=\"#coverage\""));
        assertTrue(html.contains("id=\"coverage\""));
        assertTrue(html.contains("href=\"#evidence-" + finding.get("id") + "\""));
        assertTrue(html.contains("id=\"evidence-" + finding.get("id") + "\""));
        assertFalse(html.contains("0001-01-01"));
      }
    }
  }

  String render(String... options) throws Exception {
    Path input = dir.resolve("access.log");
    Files.writeString(input, CorrelatorTest.event(0, 404).raw.replace("/.env", "/.env?q=<script>"));
    var args = new ArrayList<>(List.of(input.toString()));
    args.addAll(List.of(options));
    var out = new StringWriter();
    var err = new StringWriter();
    assertEquals(
        0,
        Main.run(
            args.toArray(String[]::new),
            out,
            err,
            Map.of("XDG_DATA_HOME", dir.toString()),
            null,
            null),
        err.toString());
    return out.toString();
  }

  @Test
  void defaultsToJapaneseAndSelectsEnglishWithoutRewritingEvidence() throws Exception {
    for (String lang : List.of("ja", "en", "ja")) {
      String html = render("--format", "html", "--lang", lang);
      assertTrue(html.contains("lang=\"" + lang + "\""));
      assertEquals(lang.equals("ja"), html.contains("成否を確認するには"));
      assertEquals(lang.equals("ja"), html.contains("成否不明"));
      assertTrue(html.contains("&lt;script&gt;"));
      assertFalse(html.contains("<script>"));
      if (lang.equals("en")) assertTrue(html.contains("Historical response bodies"));
    }
    assertTrue(render("--format", "html").contains("lang=\"ja\""));
    assertTrue(render("-format", "html", "-lang", "en").contains("lang=\"en\""));
  }

  @Test
  void rejectsLanguageBeforeReadingInputOrCreatingOutputEvenForOtherFormats() throws Exception {
    for (String lang : List.of("", "JA", "fr", "en-US")) {
      Path output = dir.resolve("must-not-exist.html");
      var out = new StringWriter();
      var err = new StringWriter();
      assertEquals(
          2,
          Main.run(
              new String[] {
                dir.resolve("missing.log").toString(),
                "--lang=" + lang,
                "--format",
                "json",
                "-o",
                output.toString()
              },
              out,
              err));
      assertTrue(err.toString().contains("--lang"));
      assertEquals("", out.toString());
      assertFalse(Files.exists(output));
    }
  }

  @Test
  void languageDoesNotChangeMachineReportsOrSummary() throws Exception {
    for (String format : List.of("json", "csv", "summary")) {
      String[] base = format.equals("summary") ? new String[0] : new String[] {"--format", format};
      var args = new ArrayList<>(List.of(base));
      args.addAll(List.of("--lang", "ja"));
      String ja = render(args.toArray(String[]::new));
      args.set(args.size() - 1, "en");
      String en = render(args.toArray(String[]::new));
      // Only the execution timestamp differs between analyses.
      assertEquals(
          ja.replaceAll("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z", "TIMESTAMP"),
          en.replaceAll("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z", "TIMESTAMP"),
          format);
    }
  }
}
