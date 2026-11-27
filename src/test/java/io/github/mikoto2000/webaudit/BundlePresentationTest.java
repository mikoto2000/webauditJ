package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BundlePresentationTest {
  @TempDir Path dir;

  @Test
  void retainsPairedOriginalReferencesWhenMaskedFileNamesCollide() throws Exception {
    Path first = dir.resolve("token=ONE.log"), second = dir.resolve("token=TWO.log");
    Files.writeString(first, BundleTest.LINE + "\n");
    Files.writeString(second, BundleTest.LINE + "\n");
    Path target = dir.resolve("paired");
    var report =
        Bundle.generate(List.of(first, second), target, new Options(), new BundleOptions());
    var inputs = Json.rows(report.get("inventory"));
    assertEquals(inputs.get(0).get("path"), inputs.get(1).get("path"));
    var ids = new HashSet<String>();
    for (var d : Json.rows(report.get("detections")))
      if (d.get("engine").equals("aura"))
        for (var ref : Json.rows(d.get("sample_evidence_refs")))
          ids.add((String) ref.get("source_file_id"));
    assertEquals(2, ids.size());
    var findings = new HashMap<String, Map<String, Object>>();
    for (var f : Json.rows(Json.obj(report.get("analysis")).get("findings")))
      findings.put((String) f.get("id"), f);
    for (var row : BundleRequestsTest.csv(target.resolve("findings.csv")))
      assertEquals(
          Json.string(findings.get(row.get("finding_id")).get("attack_score")),
          row.get("attack_score"));
  }

  @Test
  void translatesEveryStaticTemplateLabel() throws Exception {
    String template =
        new String(
            BundlePresentationTest.class.getResourceAsStream("/investigation.ftlh").readAllBytes(),
            java.nio.charset.StandardCharsets.UTF_8);
    var catalog = Json.obj(Json.resource("locales/ja.json"));
    var missing = new TreeSet<String>();
    var matcher = Pattern.compile("t\\(\"([^\"]+)\"\\)").matcher(template);
    while (matcher.find())
      if (!catalog.containsKey(matcher.group(1))) missing.add(matcher.group(1));
    assertTrue(missing.isEmpty(), missing.toString());
  }

  @Test
  void rendersAllChaptersNavigationAndCommonRecommendationsInBothLanguages() throws Exception {
    Path input = dir.resolve("access.log");
    Files.writeString(input, BundleTest.LINE + "\n");
    for (String lang : List.of("ja", "en")) {
      var options = new BundleOptions();
      options.language = lang;
      options.title = "<script>title</script>";
      Path target = dir.resolve(lang);
      var report = Bundle.generate(List.of(input), target, new Options(), options);
      String html = Files.readString(target.resolve("report.html"));
      for (int i = 1; i <= 11; i++) {
        assertTrue(html.contains("id=\"chapter-" + i + "\""));
      }
      for (int i : List.of(1, 2, 6, 8, 11))
        assertTrue(html.contains("href=\"#chapter-" + i + "\""));
      assertTrue(html.contains(lang.equals("ja") ? "第5章 推奨対応" : "5. Recommended actions"));
      assertFalse(html.contains("<script>"));
      assertTrue(html.contains("&lt;script&gt;title&lt;/script&gt;"));
      assertTrue(html.contains("<meter"));
      assertTrue(html.contains("@media print"));
      var ids = new HashSet<String>();
      var matcher = Pattern.compile("id=\"([^\"]+)\"").matcher(html);
      while (matcher.find()) assertTrue(ids.add(matcher.group(1)), "duplicate anchor");
      matcher = Pattern.compile("href=\"#([^\"]+)\"").matcher(html);
      while (matcher.find())
        assertTrue(ids.contains(matcher.group(1)), "broken link " + matcher.group(1));
      var recs = Json.rows(report.get("recommendations"));
      assertFalse(recs.isEmpty());
      assertEquals(
          recs.size(), BundleRequestsTest.csv(target.resolve("recommendations.csv")).size());
      assertEquals(
          Json.obj(report.get("statistics")).get("total_requests"),
          Json.obj(report.get("summary")).get("total_requests"));
    }
  }

  @Test
  void masksEveryPublicArtifactButPreservesOriginalAndExplicitOptOut() throws Exception {
    Path input = dir.resolve("secret.log");
    String raw = BundleTest.LINE.replace("/.env", "/.env?token=TOPSECRET") + "\n";
    Files.writeString(input, raw);
    Path target = dir.resolve("masked");
    Bundle.generate(List.of(input), target, new Options(), new BundleOptions());
    try (var files = Files.walk(target)) {
      for (Path file : files.filter(Files::isRegularFile).toList())
        assertFalse(Files.readString(file).contains("TOPSECRET"), file.toString());
    }
    assertEquals(raw, Files.readString(input));
    var sensitive = new BundleOptions();
    sensitive.includeSensitiveEvidence = true;
    Path other = dir.resolve("sensitive");
    Bundle.generate(List.of(input), other, new Options(), sensitive);
    assertTrue(Files.readString(other.resolve("suspicious-requests.csv")).contains("TOPSECRET"));
  }

  @Test
  void visiblyEscapesControlsEvenWhenSecretMaskingIsDisabled() throws Exception {
    Path input = dir.resolve("controls.log");
    Files.writeString(input, BundleTest.LINE.replace("Browser", "\u001b[31mAgent\u202e") + "\n");
    var options = new BundleOptions();
    options.includeSensitiveEvidence = true;
    var report = Bundle.generate(List.of(input), dir.resolve("report"), new Options(), options);
    String serialized = Json.MAPPER.writeValueAsString(report);
    assertFalse(serialized.contains("\u202e"));
    assertTrue(serialized.contains("\\\\u001B"));
    assertTrue(serialized.contains("\\\\u202E"));
  }
}
