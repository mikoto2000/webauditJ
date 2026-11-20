package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class InvestigationTest {
  @TempDir Path dir;

  @Test
  void sortsDeduplicatesAndKeepsUnknownTimezoneAndVerdicts() {
    var f = new Correlator.Incident();
    f.sample = CorrelatorTest.event(0, 200);
    f.sample.timezoneUnknown = true;
    f.categories.addAll(List.of("xss", "sqli", "xss", "future-category"));
    var outcome = Outcomes.infer(f);
    var guides = Json.rows(outcome.get("investigation"));
    assertEquals(List.of("future-category", "sqli", "xss"), guides.stream().map(g -> g.get("category")).toList());
    assertEquals(List.of("xss", "sqli", "xss", "future-category"), f.categories);
    assertEquals("unknown", outcome.get("verdict"));
    assertTrue(outcome.get("missing").toString().contains("timezone"));
    assertTrue(guides.get(1).get("where_to_check").toString().contains("DB"));
    assertTrue(guides.get(2).get("success_evidence").toString().contains("スクリプト"));
    f.categories.clear();
    assertEquals("unknown", Json.rows(Outcomes.infer(f).get("investigation")).getFirst().get("category"));
  }

  @Test
  void includesGuidanceInEveryFormatAndOnlyInWebAuditOutcomes() throws Exception {
    Path input = dir.resolve("access.log");
    Files.writeString(input, CorrelatorTest.event(0, 404).raw);
    var r = Engine.analyze(List.of(input), new Options());
    for (String format : List.of("json", "csv", "summary", "html")) {
      var out = new StringWriter();
      Reports.write(out, r, format);
      assertTrue(out.toString().contains("ファイル"), format);
      if (format.equals("json") || format.equals("csv")) assertTrue(out.toString().contains("where_to_check"));
      else assertTrue(out.toString().contains("何が見つかれば判断できるか"), format);
    }
    for (String set : List.of("upstream_alerts", "aura_matches", "aura_analysis"))
      if (r.get(set) != null) for (var a : Json.rows(r.get(set))) assertFalse(a.containsKey("investigation"));
  }
}
