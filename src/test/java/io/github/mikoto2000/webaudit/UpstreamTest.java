package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import java.util.stream.Stream;
import org.junit.jupiter.api.*;

class UpstreamTest {
  @TestFactory
  Stream<DynamicTest> matchesAllGoHubAndAuraFixtureResults() {
    return Json.rows(Json.resource("upstream-golden.json")).stream()
        .map(row ->
            DynamicTest.dynamicTest(
                Json.string(row.get("name")),
                () -> {
                  var u = new Upstream(new Options());
                  long line = 0;
                  for (Object text : (List<?>) row.get("lines")) {
                    line++;
                    try {
                      u.observe(LogParser.parse((String) text, "fixture.log", line, ""));
                    } catch (IllegalArgumentException ignored) {
                    }
                  }
                  var expected = Json.obj(row.get("report"));
                  equalJson(expected.get("upstream_alerts"), Core.nullable(u.alerts));
                  equalJson(expected.get("aura_matches"), Core.nullable(u.auraMatches()));
                }));
  }

  static void equalJson(Object expected, Object actual) {
    assertEquals(
        Json.MAPPER.readTree(Json.MAPPER.writeValueAsString(expected)),
        Json.MAPPER.readTree(Json.MAPPER.writeValueAsString(actual)));
  }
}
