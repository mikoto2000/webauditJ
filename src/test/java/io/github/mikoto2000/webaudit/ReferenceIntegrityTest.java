package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class ReferenceIntegrityTest {
  @Test
  void referenceGeneratorsCannotSilentlyEraseCoverage() {
    assertEquals(1321, Json.rows(Json.resource("parser-golden.json")).size());
    assertEquals(1042, Json.rows(Json.resource("detection-golden.json")).size());
    assertEquals(107, Json.rows(Json.resource("upstream-golden.json")).size());
    assertEquals(71, Json.rows(Json.resource("corpus-golden.json")).size());
    var watch = Json.rows(Json.resource("watch-golden.json"));
    assertEquals(4, watch.size());
    assertEquals(33, watch.stream().mapToInt(s -> Json.rows(s.get("steps")).size()).sum());
  }
}
