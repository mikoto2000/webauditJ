package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import org.junit.jupiter.api.Test;

class BehaviorTest {
  static Event event(int second) {
    Event e = CorrelatorTest.event(0, 404);
    e.time = e.time.plusSeconds(second);
    return e;
  }

  @Test
  void recognizesDiverseProbingAuthenticationLoginAndBursts() {
    var a = new Behavior(new Options());
    for (int i = 0; i < 620; i++) {
      Event e = event(i / 10);
      e.status = i % 2 == 0 ? 404 : 403;
      e.target = "/login/" + i;
      e.path = e.target;
      e.ua = "Scanner" + i % 6;
      e.method = "POST";
      a.observe(e, Signatures.detect(e).hits());
    }
    var ids = a.finish().stream().map(s -> s.rule().get("id")).toList();
    for (String id : List.of("WB-404", "WB-auth", "WB-rate", "WB-burst", "WB-paths", "WB-ua"))
      assertTrue(ids.contains(id), id);
  }

  @Test
  void requiresSamplesAndRetainsActualOutlierPeriod() {
    var a = new Behavior(new Options());
    for (int i = 0; i < 21; i++) {
      Event e = event(0);
      e.ip = "peer" + i;
      a.observe(e, List.of());
    }
    for (int i = 0; i < 250; i++) {
      Event e = event(i);
      e.ip = "outlier";
      a.observe(e, List.of());
    }
    var s =
        a.finish().stream()
            .filter(x -> x.rule().get("id").equals("WS-ip") && x.event().ip.equals("outlier"))
            .findFirst();
    assertTrue(s.isPresent());
    assertEquals(event(249).time, s.get().end());
  }

  @Test
  void reportsKeyBudgetAndOutOfOrderCoverage() {
    var o = new Options();
    o.maxKeys = 1;
    var a = new Behavior(o);
    a.observe(event(10), List.of());
    a.observe(event(0), List.of());
    assertFalse(a.warnings.isEmpty());
  }
}
