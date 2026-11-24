package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class ReportsTest {
  @TempDir Path dir;

  @Test
  void removesAllBidiControlsAndPreservesOrdinaryMultilingualText() {
    for (int cp :
        new int[] {
          0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068,
          0x2069
        }) assertEquals("a�b", Reports.terminal("a" + Character.toString(cp) + "b"));
    assertEquals("日本語 العربية אבג", Reports.terminal("日本語 العربية אבג"));
  }

  Map<String, Object> report() throws Exception {
    Path p = dir.resolve("a.log");
    Files.writeString(
        p, CorrelatorTest.event(0, 404).raw.replace("/.env", "/.env?q=<script>alert(1)</script>"));
    return Engine.analyze(List.of(p), new Options());
  }

  @Test
  void emitsAllFormatsAndEscapesUntrustedValues() throws Exception {
    var r = report();
    for (String format : List.of("json", "csv", "html", "summary")) {
      var out = new StringWriter();
      Reports.write(out, r, format);
      String text = out.toString();
      assertFalse(text.isEmpty(), format);
      if (format.equals("json")) UpstreamTest.equalJson(r, Json.object(text));
      if (format.equals("html")) {
        assertFalse(text.contains("<script>"));
        assertTrue(text.contains("&lt;script&gt;"));
        assertFalse(text.contains("<script src="));
      }
      if (format.equals("csv")) {
        assertTrue(
            text.startsWith(
                "record_type,id,severity,verdict,ip,observations,reasons,evidence_json,details_json"));
        assertTrue(text.contains("metadata,"));
      }
    }
  }

  @Test
  void incidentIndexLinksToEveryDetailInBothLanguages() throws Exception {
    Path input = dir.resolve("incidents.log");
    Files.writeString(
        input,
        CorrelatorTest.event(0, 404).raw
            + "\n"
            + CorrelatorTest.event(1, 200).raw.replace("192.0.2.1", "192.0.2.2")
            + "\n");
    var r = Engine.analyze(List.of(input), new Options());
    var findings = Json.rows(r.get("findings"));
    assertEquals(2, findings.size());
    for (String lang : List.of("ja", "en")) {
      var out = new StringWriter();
      Reports.write(out, r, "html", lang);
      String html = out.toString();
      int firstDetail = html.indexOf("<article id=");
      assertTrue(firstDetail > html.indexOf("id=\"incident-list\""));
      assertTrue(html.contains("id=\"incident-list\""));
      String index = html.substring(html.indexOf("<thead>"), firstDetail);
      assertEquals(2, index.split("<a href=", -1).length - 1);
      for (var finding : findings) {
        String id = finding.get("id").toString();
        assertTrue(index.contains("<a href=\"#" + id + "\">" + id + "</a>"));
        assertEquals(1, html.split("<article id=\"" + id + "\">", -1).length - 1);
        assertTrue(index.contains(finding.get("ip").toString()));
        int at = html.indexOf("<article id=\"" + id + "\">");
        String section = html.substring(at, html.indexOf("</article>", at));
        String backLabel = lang.equals("ja") ? "事案の一覧表に戻る" : "Back to incident list";
        assertTrue(section.contains("<a href=\"#incident-list\">" + backLabel + "</a>"));
      }
    }
  }

  @Test
  void emptyIncidentListKeepsExplanationWithoutIndex() throws Exception {
    Path input = dir.resolve("empty.log");
    Files.writeString(input, "");
    var out = new StringWriter();
    Reports.write(out, Engine.analyze(List.of(input), new Options()), "html", "en");
    String html = out.toString();
    assertTrue(html.contains("No WebAudit incidents."));
    assertFalse(
        html.substring(0, html.indexOf("Independent Hub and Aura detections")).contains("<thead>"));
    assertFalse(html.contains("<article"));
  }

  @Test
  void upstreamIndexLinksToDistinctDetailsAndPreservesEvidence() throws Exception {
    var r = report();
    for (String key : List.of("upstream_alerts", "aura_matches", "aura_analysis")) {
      r.put(
          key,
          List.of(
              Json.map(
                  "source",
                  key,
                  "rule_id",
                  "same-rule",
                  "ip",
                  "192.0.2.5",
                  "group",
                  "<group>",
                  "count",
                  3,
                  "wall_first",
                  "wall-start",
                  "wall_last",
                  "wall-end",
                  "events",
                  List.of(Json.map("file", "<source.log>", "line", 42)),
                  "evidence_truncated",
                  true,
                  "metadata",
                  Json.map("<key>", "<value>"))));
    }
    for (String lang : List.of("ja", "en")) {
      var out = new StringWriter();
      Reports.write(out, r, "html", lang);
      String html = out.toString();
      int start = html.indexOf("<a href=\"#upstream-");
      int detail = html.indexOf("<article id=\"upstream-");
      assertTrue(start > 0 && detail > start);
      assertTrue(html.substring(0, start).contains("id=\"upstream-list\""));
      String index = html.substring(start, detail);
      assertEquals(3, index.split("<a href=", -1).length - 1);
      assertFalse(index.contains("&lt;source.log&gt;"));
      for (int i = 0; i < 3; i++) {
        assertTrue(index.contains("href=\"#upstream-" + i + "\">same-rule</a>"));
        assertEquals(1, html.split("<article id=\"upstream-" + i + "\">", -1).length - 1);
        int at = html.indexOf("<article id=\"upstream-" + i + "\">");
        String section = html.substring(at, html.indexOf("</article>", at));
        assertTrue(section.contains("&lt;source.log&gt;:42"));
        assertTrue(section.contains("&lt;key&gt;</dt><dd>&lt;value&gt;"));
        assertTrue(section.contains("wall-start") && section.contains("wall-end"));
        assertTrue(section.contains("class=\"warning\""));
        String backLabel =
            lang.equals("ja") ? "Hub・Auraの検出一覧表に戻る" : "Back to Hub and Aura detection list";
        assertTrue(section.contains("<a href=\"#upstream-list\">" + backLabel + "</a>"));
      }
      assertFalse(html.contains("<group>"));
    }
  }

  @Test
  void propagatesWriteFailuresAndNeutralizesTerminalAndCsvControls() throws Exception {
    var r = report();
    r.put("warnings", List.of("bad\u001b[31m\u202e"));
    var out = new StringWriter();
    Reports.write(out, r, "summary");
    assertFalse(out.toString().contains("\u001b"));
    assertFalse(out.toString().contains("\u202e"));
    Writer broken =
        new Writer() {
          public void write(char[] c, int a, int b) throws IOException {
            throw new IOException("broken");
          }

          public void flush() {}

          public void close() {}
        };
    for (String format : List.of("json", "csv", "html", "summary"))
      assertThrows(IOException.class, () -> Reports.write(broken, r, format));
  }
}
