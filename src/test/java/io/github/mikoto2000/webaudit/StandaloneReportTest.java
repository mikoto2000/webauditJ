package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class StandaloneReportTest {
  @TempDir Path dir;

  int run(Writer out, String... args) {
    return Main.run(
        args, out, new StringWriter(), Map.of("XDG_DATA_HOME", dir.toString()), null, null);
  }

  @Test
  void cliEmbedsTechnicalReportScriptsAndMaskedAnnexesInBothLanguages() throws Exception {
    Path input = dir.resolve("access.log");
    String raw =
        BundleTest.LINE.replace(
            "/.env", "/.env?token=TOPSECRET&x=</script><script>alert(1)</script>");
    Files.writeString(input, raw + "\n");
    for (String lang : List.of("ja", "en")) {
      Path file = dir.resolve(lang + ".html");
      assertEquals(
          0,
          run(
              new StringWriter(),
              input.toString(),
              "-o",
              file.toString(),
              "--lang",
              lang,
              "--report-title",
              "<custom title>"));
      String page = Files.readString(file);
      for (String marker :
          List.of(
              "id=\"chapter-8\"",
              "id=\"investigation-workflow\"",
              "id=\"secondary-prompt\"",
              "id=\"appendix-statistics\"",
              "<html lang=\"" + lang + "\"",
              "&lt;custom title&gt;")) assertTrue(page.contains(marker), marker);
      assertFalse(page.contains("TOPSECRET"));
      assertFalse(page.contains("<script>alert(1)</script>"));
      assertTrue(page.contains("&lt;script&gt;"));
      assertFalse(page.contains("<script src="));
      assertFalse(page.contains("script-src 'self'"));
      var links = Pattern.compile("href=\"([^\"]+)\"").matcher(page);
      boolean structured = false;
      while (links.find()) {
        String ref = links.group(1);
        assertTrue(ref.startsWith("#") || ref.contains(":"), ref);
        if (ref.startsWith("data:application/octet-stream;base64,")) {
          String decoded =
              new String(
                  Base64.getDecoder().decode(ref.substring(ref.indexOf(',') + 1)),
                  StandardCharsets.UTF_8);
          assertFalse(decoded.contains("TOPSECRET"));
          if (decoded.contains("\"schema\" : \"webaudit/investigation-1\"")) {
            var report = Json.object(decoded);
            assertEquals(1, Json.number(Json.obj(report.get("analysis")).get("requests")));
            for (var finding : Json.rows(Json.obj(report.get("analysis")).get("findings")))
              assertTrue(page.contains("id=\"" + finding.get("id") + "\""));
            structured = true;
          }
        }
      }
      assertTrue(structured, "embedded report.json");
      var scripts = Pattern.compile("(?s)<script>(.*?)</script>").matcher(page);
      int count = 0;
      while (scripts.find()) {
        String normalized = scripts.group(1).replace("\r\n", "\n").replace('\r', '\n');
        String hash =
            Base64.getEncoder()
                .encodeToString(Bundle.sha().digest(normalized.getBytes(StandardCharsets.UTF_8)));
        assertTrue(page.contains("'sha256-" + hash + "'"));
        count++;
      }
      assertEquals(2, count);
      var options = new BundleOptions();
      options.language = lang;
      options.title = "<custom title>";
      Path bundle = dir.resolve(lang);
      Bundle.generate(List.of(input), bundle, new Options(), options);
      BundleAudienceTest.verifyBrowser(bundle, file);
    }
    assertEquals(raw + "\n", Files.readString(input));
    var stdout = new StringWriter();
    assertEquals(0, run(stdout, input.toString(), "--format", "html"));
    assertTrue(stdout.toString().contains("id=\"investigation-workflow\""));
    Path failed = dir.resolve("too-small.html");
    assertEquals(
        1,
        run(
            new StringWriter(),
            input.toString(),
            "-o",
            failed.toString(),
            "--max-report-bytes",
            "32"));
    assertFalse(Files.exists(failed));
    Path sensitive = dir.resolve("sensitive.html");
    assertEquals(
        0,
        run(
            new StringWriter(),
            input.toString(),
            "-o",
            sensitive.toString(),
            "--include-sensitive-evidence"));
    assertTrue(Files.readString(sensitive).contains("TOPSECRET"));
  }

  @Test
  void compressedInputGeoipAndEmbeddedByteBudgetUseCommonModel() throws Exception {
    Path input = dir.resolve("access.log.gz");
    try (var out = new java.util.zip.GZIPOutputStream(Files.newOutputStream(input))) {
      out.write(
          (BundleTest.LINE.replace("192.0.2.1", "8.8.8.8") + "\n")
              .getBytes(StandardCharsets.UTF_8));
    }
    Path output = dir.resolve("geoip.html");
    assertEquals(
        0,
        run(
            new StringWriter(),
            input.toString(),
            "-o",
            output.toString(),
            "--geoip-country",
            GeoIPTest.db("country"),
            "--geoip-asn",
            GeoIPTest.db("asn")));
    assertTrue(Files.readString(output).contains("64500"));
    Path bundle = dir.resolve("bundle");
    Bundle.generate(List.of(input), bundle, new Options(), new BundleOptions());
    String page = Files.readString(bundle.resolve("technical-report.html"));
    String script = Files.readString(bundle.resolve("secondary-investigation.js"));
    Files.writeString(
        bundle.resolve("secondary-investigation.js"),
        script.replace("\r\n", "\n").replace("\n", "\r\n"));
    String embedded = StandaloneReport.embed(page, bundle, 1L << 30, "ja");
    long bytes = embedded.getBytes(StandardCharsets.UTF_8).length;
    assertEquals(embedded, StandaloneReport.embed(page, bundle, bytes + 512, "ja"));
    assertThrows(IOException.class, () -> StandaloneReport.embed(page, bundle, bytes - 1, "ja"));
    assertTrue(
        embedded.contains(
            "'sha256-"
                + Base64.getEncoder()
                    .encodeToString(
                        Bundle.sha()
                            .digest(
                                script
                                    .replace("\r\n", "\n")
                                    .replace('\r', '\n')
                                    .getBytes(StandardCharsets.UTF_8)))
                + "'"));
  }

  @Test
  void bundleHasOnlyTwoAudienceReportsAndNoObsoleteManifestEntry() throws Exception {
    Path input = dir.resolve("access.log"), out = dir.resolve("bundle");
    Files.writeString(input, BundleTest.LINE + "\n");
    Bundle.generate(List.of(input), out, new Options(), new BundleOptions());
    assertFalse(Files.exists(out.resolve("report.html")));
    var manifest = Json.object(Files.readString(out.resolve("manifest.json")));
    assertFalse(
        Json.rows(manifest.get("artifacts")).stream()
            .anyMatch(a -> "report.html".equals(a.get("path"))));
    assertTrue(Files.isRegularFile(out.resolve("executive-summary.html")));
    assertTrue(Files.isRegularFile(out.resolve("technical-report.html")));
  }
}
