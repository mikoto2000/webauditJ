package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.util.stream.Stream;
import org.junit.jupiter.api.*;

class SignaturesTest {
  @TestFactory
  Stream<DynamicTest> matchesGoRulesOnAllAcceptedFixtures() {
    return Json.rows(Json.resource("detection-golden.json")).stream()
        .map(r ->
            DynamicTest.dynamicTest(
                Json.string(r.get("input")),
                () -> {
                  Event e =
                      LogParser.parse(
                          Json.string(r.get("input")),
                          "fixture.log",
                          1,
                          Json.string(r.get("custom")));
                  var d = Signatures.detect(e);
                  assertEquals(r.get("hits"), d.hits().stream().map(h -> h.get("id")).toList());
                }));
  }

  @Test
  void sensitiveProbeIsDetectedButAdminAndNormalClientsAreNot() {
    Event e = new Event();
    e.target = "/.env";
    assertFalse(Signatures.detect(e).hits().isEmpty());
    e.target = "/admin";
    e.ua = "curl/8.0";
    assertTrue(Signatures.detect(e).hits().isEmpty());
  }
}
