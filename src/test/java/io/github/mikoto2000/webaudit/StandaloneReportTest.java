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
    return Main.run(args, out, new StringWriter(), Map.of("XDG_DATA_HOME", dir.toString()), null, null);
  }

  @Test
  void cliEmbedsTechnicalReportScriptsAndMaskedAnnexesInBothLanguages() throws Exception {
    Path input = dir.resolve("access.log");
    String raw = BundleTest.LINE.replace("/.env", "/.env?token=TOPSECRET&x=</script><script>alert(1)</script>");
    Files.writeString(input, raw + "\n");
    for (String lang : List.of("ja", "en")) {
      Path file = dir.resolve(lang + ".html");
      assertEquals(0, run(new StringWriter(), input.toString(), "-o", file.toString(), "--lang", lang,
          "--report-title", "<custom title>"));
      String page = Files.readString(file);
      for (String marker : List.of("id=\"chapter-8\"", "id=\"investigation-workflow\"",
          "id=\"secondary-prompt\"", "id=\"appendix-statistics\"", "<html lang=\"" + lang + "\"", "&lt;custom title&gt;"))
        assertTrue(page.contains(marker), marker);
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
          String decoded = new String(Base64.getDecoder().decode(ref.substring(ref.indexOf(',') + 1)), StandardCharsets.UTF_8);
          assertFalse(decoded.contains("TOPSECRET"));
          if (decoded.contains("\"schema\" : \"webaudit/investigation-1\"")) {
            var report = Json.object(decoded);
            assertEquals(1, Json.number(Json.obj(report.get("analysis")).get("parsed")));
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
        String hash = Base64.getEncoder().encodeToString(Bundle.sha().digest(normalized.getBytes(StandardCharsets.UTF_8)));
        assertTrue(page.contains("'sha256-" + hash + "'"));
        count++;
      }
      assertEquals(2, count);
    }
    assertEquals(raw + "\n", Files.readString(input));
    var stdout = new StringWriter();
    assertEquals(0, run(stdout, input.toString(), "--format", "html"));
    assertTrue(stdout.toString().contains("id=\"investigation-workflow\""));
    Path failed = dir.resolve("too-small.html");
    assertEquals(1, run(new StringWriter(), input.toString(), "-o", failed.toString(), "--max-report-bytes", "32"));
    assertFalse(Files.exists(failed));
    Path sensitive = dir.resolve("sensitive.html");
    assertEquals(0, run(new StringWriter(), input.toString(), "-o", sensitive.toString(), "--include-sensitive-evidence"));
    assertTrue(Files.readString(sensitive).contains("TOPSECRET"));
  }

  @Test
  void bundleHasOnlyTwoAudienceReportsAndNoObsoleteManifestEntry() throws Exception {
    Path input = dir.resolve("access.log"), out = dir.resolve("bundle");
    Files.writeString(input, BundleTest.LINE + "\n");
    Bundle.generate(List.of(input), out, new Options(), new BundleOptions());
    assertFalse(Files.exists(out.resolve("report.html")));
    var manifest = Json.object(Files.readString(out.resolve("manifest.json")));
    assertFalse(Json.rows(manifest.get("artifacts")).stream().anyMatch(a -> "report.html".equals(a.get("path"))));
    assertTrue(Files.isRegularFile(out.resolve("executive-summary.html")));
    assertTrue(Files.isRegularFile(out.resolve("technical-report.html")));
  }
}
