package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class ReportLanguageTest {
  @TempDir Path dir;

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
          ja.replaceAll("\"analyzed_at\"[^\\n]*", "TIMESTAMP"),
          en.replaceAll("\"analyzed_at\"[^\\n]*", "TIMESTAMP"),
          format);
    }
  }
}
