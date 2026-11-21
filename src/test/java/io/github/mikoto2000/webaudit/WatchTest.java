package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class WatchTest {
  @Test
  void goV2WatchParity() {
    for (var scenario : Json.rows(Json.resource("watch-golden.json"))) {
      var engine = new WatchEngine(new WatchCommand.Arguments(), null, s -> {});
      int line = 0;
      for (var step : Json.rows(scenario.get("steps"))) {
        var now = NOW.plusSeconds(Json.number(step.get("at")));
        if (!Json.string(step.get("line")).isEmpty())
          engine.observe(
              LogParser.parse(Json.string(step.get("line")), "access.log", ++line, ""), now);
        Object expected = step.get("events");
        if (expected == null) expected = List.of();
        Object actual = Json.MAPPER.readValue(Json.string(engine.flush(now)), Object.class);
        assertEquals(expected, actual, scenario.get("name") + " step " + line);
      }
    }
  }

  @TempDir Path dir;
  static final Instant NOW = Instant.parse("2026-11-21T00:00:00Z");

  static String log(String target) {
    return "198.51.100.1 - - [21/Nov/2026:00:00:00 +0000] \"GET "
        + target
        + " HTTP/1.1\" 404 12 \"-\" \"secret-agent\"";
  }

  @Test
  void lifecycleAndPrivacy() {
    var o = new WatchCommand.Arguments();
    var engine = new WatchEngine(o, null, s -> {});
    assertTrue(engine.observe(LogParser.parse(log("/.env?secret=abc"), "access.log", 1, ""), NOW));
    var created = engine.flush(NOW);
    assertFalse(created.isEmpty());
    var first = created.getFirst();
    assertEquals("incident_created", first.get("event_type"));
    assertFalse(Json.string(engine.snapshot()).contains("secret"));
    assertFalse(Json.string(first).contains("secret"));
    engine.observe(
        LogParser.parse(log("/.env?secret=abc"), "access.log", 2, ""), NOW.plusSeconds(1));
    var updated = engine.flush(NOW.plusSeconds(1)).getFirst();
    assertEquals(first.get("incident_id"), updated.get("incident_id"));
    assertEquals(2, Json.number(updated.get("revision")));
    assertEquals("incident_updated", updated.get("event_type"));
    assertEquals(
        "incident_closed", engine.flush(NOW.plusSeconds(332)).getFirst().get("event_type"));
    assertFalse(
        engine.observe(LogParser.parse(log("/.env"), "access.log", 3, ""), NOW.plusSeconds(333)));
  }

  @Test
  void readerPartialTruncateAndResume() throws Exception {
    Path file = dir.resolve("access.log");
    Files.writeString(file, log("/.env").substring(0, 20));
    var o = new WatchCommand.Arguments();
    o.from = "beginning";
    o.inputs.add(file);
    var lines = new ArrayList<String>();
    Map<String, Object> state;
    try (var r = new WatchReader(o, s -> {})) {
      r.poll((text, path, n) -> lines.add(text));
      assertTrue(lines.isEmpty());
      state = r.snapshot();
    }
    Files.writeString(file, log("/.env").substring(20) + "\n", StandardOpenOption.APPEND);
    try (var r = new WatchReader(o, s -> {})) {
      r.restore(state);
      r.poll((text, path, n) -> lines.add(text));
      assertEquals(List.of(log("/.env")), lines);
      Files.writeString(file, "short\n");
      r.poll((text, path, n) -> lines.add(text));
      assertEquals("short", lines.getLast());
    }
  }

  @Test
  void defaultEndDiscardsExistingPartialLine() throws Exception {
    Path file = dir.resolve("access.log");
    Files.writeString(file, "partial");
    var o = new WatchCommand.Arguments();
    o.inputs.add(file);
    try (var r = new WatchReader(o, s -> {})) {
      Files.writeString(file, " remainder\nnew\n", StandardOpenOption.APPEND);
      var lines = new ArrayList<String>();
      r.poll((t, p, n) -> {
        lines.add(t);
        assertEquals(0, n);
      });
      assertEquals(List.of("new"), lines);
    }
  }

  @Test
  void stateChecksumAndLock() throws Exception {
    var targets = List.of(dir.resolve("access.log").toString());
    try (var store = new WatchStore(dir.resolve("state"), targets, "config", false)) {
      assertNull(store.load());
      store.save(Json.map("test", 123));
      assertEquals(123, Json.number(store.load().get("test")));
      assertThrows(
          Exception.class, () -> new WatchStore(dir.resolve("state"), targets, "config", false));
      Files.writeString(store.path, "{}");
      assertThrows(Exception.class, store::load);
    }
  }

  @Test
  void rejectsFutureAndLateEvents() {
    var engine = new WatchEngine(new WatchCommand.Arguments(), null, s -> {});
    var e = LogParser.parse(log("/.env"), "access.log", 1, "");
    assertFalse(engine.observe(e, NOW.minusSeconds(301)));
    assertTrue(engine.observe(e, NOW));
    var old = e.copy();
    old.time = old.time.minusSeconds(31);
    assertFalse(engine.observe(old, NOW));
  }

  @Test
  void cliValidation() {
    for (String[] args :
        List.of(
            new String[] {"watch", "x", "--format", "html"},
            new String[] {"watch", "x", "--poll-interval", "1ms"},
            new String[] {"watch", "x", "--on-detect-arg=a"})) {
      assertEquals(2, Main.run(args, new java.io.StringWriter(), new java.io.StringWriter()));
    }
  }

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.CsvSource({
    "--from,invalid", "--format,json", "--poll-interval,9ms", "--poll-interval,61s",
    "--max-files,0", "--max-files,4097", "--max-events,0", "--max-events,100001",
    "--max-line-bytes,0", "--max-line-bytes,16777217", "--allowed-lateness,0s",
        "--allowed-lateness,2h",
    "--retention,5m", "--retention,25h", "--hook-timeout,0ms", "--hook-timeout,2h",
    "--hook-concurrency,0", "--hook-concurrency,33", "--hook-queue-size,0",
        "--hook-queue-size,4097",
    "--on-detect-severity,extreme", "--on-detect-event,closed", "--include,[", "--log-regex,x"
  })
  void invalidOptionsFailBeforeCreatingState(String option, String value) {
    assertEquals(
        2,
        Main.run(
            new String[] {"watch", dir.resolve("access.log").toString(), option, value},
            new java.io.StringWriter(),
            new java.io.StringWriter()));
  }
}
