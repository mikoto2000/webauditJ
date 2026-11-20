package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import org.junit.jupiter.api.Test;

class CorrelatorTest {
  static Event event(int i, int status) {
    return LogParser.parse(
        "192.0.2.1 - - [01/Nov/2026:00:00:"
            + String.format("%02d", i)
            + " +0000] \"GET /.env HTTP/1.1\" "
            + status
            + " 42 \"-\" \"Browser\"",
        "a.log",
        i + 1,
        "");
  }

  @Test
  void outcomesRequireMultipleObservationsAndDoNotClaimConfirmation() {
    for (var sample :
        List.of(
            List.of(200),
            List.of(500),
            List.of(302),
            List.of(404),
            List.of(403, 404, 403),
            List.of(404, 200, 200),
            List.of(403, 404, 403, 500))) {
      var c = new Correlator(new Options());
      for (int i = 0; i < sample.size(); i++) {
        var e = event(i, sample.get(i));
        c.add(e, Signatures.detect(e));
      }
      var f = c.finish();
      assertEquals(1, f.size());
      String want =
          sample.equals(List.of(403, 404, 403))
              ? "likely_failed"
              : sample.equals(List.of(404, 200, 200)) ? "possible_success" : "unknown";
      assertEquals(want, Json.obj(f.getFirst().get("outcome")).get("verdict"));
    }
  }

  @Test
  void separatesHostUaAndTimeButCapsEvidenceAndScores() {
    var c = new Correlator(new Options());
    for (int i = 0; i < 40; i++) {
      var e = event(i, 404);
      c.add(e, Signatures.detect(e));
    }
    assertEquals(1, c.finish().size());
    assertEquals(8, ((List<?>) c.finish().getFirst().get("evidence")).size());
    Event e = event(41, 404);
    e.host = "other";
    c.add(e, Signatures.detect(e));
    assertEquals(2, c.finish().size());
  }

  @Test
  void preservesUnknownTimezoneAndRespectsEvidenceBudget() {
    var o = new Options();
    o.maxEvidenceBytes = 100;
    var c = new Correlator(o);
    var e = event(0, 200);
    e.timezoneUnknown = true;
    c.add(e, Signatures.detect(e));
    var f = c.finish().getFirst();
    assertNull(f.get("first"));
    assertEquals("unknown", Json.obj(f.get("outcome")).get("verdict"));
    assertFalse(c.warnings.isEmpty());
  }

  @Test
  void unknownClockIdsDependOnSourceFile() {
    Event a = event(0, 404);
    a.timezoneUnknown = true;
    Event b = a.copy();
    b.file = "other.log";
    var c = new Correlator(new Options());
    c.add(a, Signatures.detect(a));
    c.add(b, Signatures.detect(b));
    assertEquals(2, c.finish().size());
    assertNotEquals(c.finish().get(0).get("id"), c.finish().get(1).get("id"));
  }
}
