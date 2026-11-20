package io.github.mikoto2000.webaudit;

import java.util.*;
import java.util.stream.Stream;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

class AuraAnalysisTest {
  @Test
  void existingAggregatesKeepCountingAtCapacityAndNewTablesShareTheBudget() {
    var o = new Options();
    o.maxKeys = 4;
    var a = new AuraAnalysis(o);
    for (int i = 0; i < 20; i++) a.observe(CorrelatorTest.event(i, 403));
    var brute = a.finish().stream().filter(f -> f.get("rule_id").equals("brute_force")).findFirst();
    assertTrue(brute.isPresent());
    assertEquals(20, Json.number(brute.get().get("count")));
    assertTrue(a.finish().stream().noneMatch(f -> f.get("rule_id").equals("rare_user_agent")));
    // A rejected peer may still update an existing UA/hour, but cannot add a UA of its own.
    var newcomer = CorrelatorTest.event(21, 403);
    newcomer.ip = "192.0.2.2";
    newcomer.ua = "NewBrowser";
    a.observe(newcomer);
    assertEquals(1, a.warnings.size());
    assertTrue(a.finish().stream().noneMatch(f -> "NewBrowser".equals(f.get("group"))));
  }

  @Test
  void oneKeyAdmitsOnlyThePeerAndKeepsIts404Observations() {
    var o = new Options();
    o.maxKeys = 1;
    var a = new AuraAnalysis(o);
    for (int i = 0; i < 50; i++) a.observe(CorrelatorTest.event(i, 404));
    var result = a.finish();
    assertEquals(1, result.size());
    assertEquals("enumeration_404", result.getFirst().get("rule_id"));
    assertEquals(50, Json.number(result.getFirst().get("count")));
    assertEquals(1, a.warnings.size());
  }

  @TestFactory
  Stream<DynamicTest> matchesGoCaseAggregations() {
    return Json.rows(Json.resource("upstream-golden.json")).stream()
        .map(row ->
            DynamicTest.dynamicTest(
                Json.string(row.get("name")),
                () -> {
                  var a = new AuraAnalysis(new Options());
                  long line = 0;
                  for (Object text : (List<?>) row.get("lines")) {
                    line++;
                    try {
                      a.observe(LogParser.parse((String) text, "fixture.log", line, ""));
                    } catch (IllegalArgumentException ignored) {
                    }
                  }
                  UpstreamTest.equalJson(
                      Json.obj(row.get("report")).get("aura_analysis"), Core.nullable(a.finish()));
                }));
  }
}
