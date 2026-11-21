package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class WatchIntegrationTest {
  @TempDir Path dir;

  static void until(java.util.function.BooleanSupplier test) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (!test.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(10);
    assertTrue(test.getAsBoolean(), "condition timed out");
  }

  public static class Child {
    public static void main(String[] args) throws Exception {
      switch (args[0]) {
        case "watch" -> {
          Thread.ofPlatform()
              .daemon()
              .start(() -> {
                try {
                  Thread.sleep(1500);
                } catch (InterruptedException ignored) {
                }
                System.exit(0);
              });
          Main.main(Arrays.copyOfRange(args, 1, args.length));
        }
        case "echo" ->
            Files.writeString(
                Path.of(args[1]),
                Json.string(
                    Json.map(
                        "input",
                        new String(
                            System.in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8),
                        "args",
                        List.of(args).subList(2, args.length))));
        case "fail" -> {
          System.out.print("x".repeat(100000));
          System.err.print("SECRET".repeat(20000));
          System.exit(7);
        }
        case "sleep" -> Thread.sleep(60000);
        case "tree" -> {
          var p =
              new ProcessBuilder(
                      java(),
                      "-cp",
                      System.getProperty("java.class.path"),
                      Child.class.getName(),
                      "sleep")
                  .start();
          Files.writeString(Path.of(args[1]), Long.toString(p.pid()));
          Thread.sleep(60000);
        }
      }
    }
  }

  static String java() {
    return Path.of(
            System.getProperty("java.home"),
            "bin",
            Main.os().equals("windows") ? "java.exe" : "java")
        .toString();
  }

  static WatchHooks.Hook hook(String... args) {
    var list =
        new ArrayList<>(
            List.of("-cp", System.getProperty("java.class.path"), Child.class.getName()));
    list.addAll(List.of(args));
    return new WatchHooks.Hook(java(), list);
  }

  static Map<String, Object> event() {
    return Json.map(
        "schema_version",
        1,
        "incident_id",
        "WA-test",
        "event_id",
        "evt-test",
        "revision",
        1,
        "event_type",
        "incident_created",
        "severity",
        "high",
        "outcome",
        "unknown");
  }

  @Test
  void hookLiteralJsonDedupAndRestore() throws Exception {
    Path output = dir.resolve("space output.json");
    String literal = "$(touch BAD); & <script> \"\\";
    var o = new WatchCommand.Arguments();
    o.hooks.add(hook("echo", output.toString(), literal, "a b"));
    var warnings = new CopyOnWriteArrayList<String>();
    Map<String, Object> history;
    try (var h = new WatchHooks(o, warnings::add, null)) {
      h.dispatch(event(), true);
      h.dispatch(event(), true);
      until(() -> Files.exists(output) && size(output) > 0);
      until(() -> h.pool.getCompletedTaskCount() == 1);
      var saved = Json.object(Files.readString(output));
      assertEquals(List.of(literal, "a b"), saved.get("args"));
      var payload = Json.object(Json.string(saved.get("input")));
      assertTrue(Json.string(payload.get("notification_id")).startsWith("notification-"));
      assertEquals("evt-test", payload.get("event_id"));
      history = h.snapshot();
      assertEquals(1, h.pool.getCompletedTaskCount());
    }
    try (var h = new WatchHooks(o, warnings::add, history)) {
      h.dispatch(event(), true);
      assertEquals(0, h.pool.getTaskCount());
    }
    assertTrue(warnings.isEmpty(), warnings.toString());
  }

  static long size(Path p) {
    try {
      return Files.size(p);
    } catch (IOException ex) {
      return 0;
    }
  }

  @Test
  void hookTimeoutKillsDescendants() throws Exception {
    Path marker = dir.resolve("pid");
    var o = new WatchCommand.Arguments();
    o.hookTimeout = "2s";
    o.hooks.add(hook("tree", marker.toString()));
    var warnings = new CopyOnWriteArrayList<String>();
    try (var h = new WatchHooks(o, warnings::add, null)) {
      h.dispatch(event(), true);
      until(() -> size(marker) > 0);
      long pid = Long.parseLong(Files.readString(marker));
      until(() -> h.pool.getCompletedTaskCount() == 1);
      until(() -> ProcessHandle.of(pid).map(p -> !p.isAlive()).orElse(true));
    }
    assertTrue(warnings.contains("hook timed out"), warnings.toString());
  }

  @Test
  void hookCancellationKillsDescendants() throws Exception {
    Path marker = dir.resolve("pid");
    var o = new WatchCommand.Arguments();
    o.hooks.add(hook("tree", marker.toString()));
    var h = new WatchHooks(o, s -> {}, null);
    try {
      h.dispatch(event(), true);
      until(() -> size(marker) > 0);
    } finally {
      h.close();
    }
    long pid = Long.parseLong(Files.readString(marker));
    until(() -> ProcessHandle.of(pid).map(p -> !p.isAlive()).orElse(true));
  }

  @Test
  void hookFiltersFailuresQueueAndOutputDrain() throws Exception {
    var o = new WatchCommand.Arguments();
    o.hooks.add(hook("fail"));
    o.events = "all";
    o.queue = 1;
    var warnings = new CopyOnWriteArrayList<String>();
    try (var h = new WatchHooks(o, warnings::add, null)) {
      var event = event();
      event.put("severity", "medium");
      h.dispatch(event, true);
      assertEquals(0, h.pool.getTaskCount());
      event.put("severity", "high");
      h.dispatch(event, false);
      assertEquals(0, h.pool.getTaskCount());
      h.dispatch(event, true);
      until(() -> h.pool.getCompletedTaskCount() == 1);
      assertTrue(warnings.contains("hook failed with exit code 7"), warnings.toString());
      assertFalse(warnings.toString().contains("SECRET"));
      for (int i = 2; i < 100; i++) {
        event.put("revision", i);
        h.dispatch(new LinkedHashMap<>(event), true);
      }
      assertTrue(h.dropped > 0);
    }
  }

  @Test
  void renameDrainsOldHandleAndReadsReplacementFromBeginning() throws Exception {
    Path file = dir.resolve("access.log");
    Files.writeString(file, "old1\n");
    var o = new WatchCommand.Arguments();
    o.from = "beginning";
    o.inputs.add(file);
    try (var reader = new WatchReader(o, s -> {})) {
      var lines = new ArrayList<String>();
      reader.poll((t, p, n) -> lines.add(t));
      Path old = dir.resolve("access.log.1");
      Files.move(file, old);
      Files.writeString(old, "old2\n", StandardOpenOption.APPEND);
      Files.writeString(file, "new1\n");
      reader.poll((t, p, n) -> lines.add(t));
      reader.poll((t, p, n) -> lines.add(t));
      assertEquals(List.of("old1", "old2", "new1"), lines);
    }
  }

  @Test
  void directorySelectionAndMissingFileCreation() throws Exception {
    Files.writeString(dir.resolve("access.log"), "a\n");
    Files.writeString(dir.resolve("error.log"), "b\n");
    Files.writeString(dir.resolve("access.log.1"), "c\n");
    Files.createDirectory(dir.resolve("sub"));
    Files.writeString(dir.resolve("sub/access.log"), "d\n");
    var o = new WatchCommand.Arguments();
    o.from = "beginning";
    o.inputs.add(dir);
    try (var r = new WatchReader(o, s -> {})) {
      var lines = new ArrayList<String>();
      r.poll((t, p, n) -> lines.add(t));
      assertEquals(List.of("a"), lines);
      Files.writeString(dir.resolve("site-access.log"), "e\n");
      r.poll((t, p, n) -> lines.add(t));
      assertEquals(List.of("a", "e"), lines);
    }
    o.inputs = List.of(dir.resolve("missing.log"));
    try (var r = new WatchReader(o, s -> {})) {
      Files.writeString(o.inputs.getFirst(), "created\n");
      var lines = new ArrayList<String>();
      r.poll((t, p, n) -> lines.add(t));
      assertEquals(List.of("created"), lines);
    }
  }

  @Test
  void emptyTailStartsWithKnownLineOne() throws Exception {
    Path file = dir.resolve("access.log");
    Files.createFile(file);
    var o = new WatchCommand.Arguments();
    o.inputs.add(file);
    try (var r = new WatchReader(o, s -> {})) {
      Files.writeString(file, "new\n");
      var lines = new ArrayList<Long>();
      r.poll((t, p, n) -> lines.add(n));
      assertEquals(List.of(1L), lines);
    }
  }

  @Test
  void temporaryReadFailureDoesNotDetachFile() throws Exception {
    if (!Main.os().equals("windows"))
      return; // Windows byte-range locks deny reads by other handles.
    Path file = dir.resolve("access.log");
    Files.writeString(file, "new\n");
    var o = new WatchCommand.Arguments();
    o.inputs.add(file);
    o.from = "beginning";
    var warnings = new ArrayList<String>();
    var lines = new ArrayList<String>();
    try (var r = new WatchReader(o, warnings::add);
        var locked = java.nio.channels.FileChannel.open(file, StandardOpenOption.WRITE)) {
      try (var lock = locked.lock()) {
        r.poll((t, p, n) -> lines.add(t));
        assertTrue(lines.isEmpty());
      }
      r.poll((t, p, n) -> lines.add(t));
      assertEquals(List.of("new"), lines);
      assertFalse(warnings.isEmpty());
      assertNull(r.files.getFirst().detached);
    }
  }

  @Test
  void downtimeRotationRecoversUnconsumedOldFile() throws Exception {
    Path file = dir.resolve("access.log");
    Files.writeString(file, "before\npartial");
    var o = new WatchCommand.Arguments();
    o.inputs.add(file);
    o.from = "beginning";
    Map<String, Object> saved;
    try (var r = new WatchReader(o, s -> {})) {
      r.poll((t, p, n) -> {});
      saved = r.snapshot();
    }
    Path rotated = dir.resolve("access.log.1");
    Files.move(file, rotated);
    Files.writeString(rotated, "-after\n", StandardOpenOption.APPEND);
    Files.writeString(file, "new\n");
    var lines = new ArrayList<String>();
    try (var r = new WatchReader(o, s -> {})) {
      r.restore(saved);
      r.poll((t, p, n) -> lines.add(t));
      r.poll((t, p, n) -> lines.add(t));
    }
    assertEquals(List.of("partial-after", "new"), lines);
  }

  @Test
  void noStateIgnoresStateRootAndResetRecoversCorruption() throws Exception {
    Path log = dir.resolve("access.log");
    Files.writeString(log, WatchTest.log("/.env") + "\n");
    var env = new HashMap<>(System.getenv());
    env.put("XDG_STATE_HOME", "relative-invalid");
    env.put("XDG_DATA_HOME", dir.resolve("data").toString());
    var out = new StringWriter();
    var err = new StringWriter();
    var stop = new java.util.concurrent.atomic.AtomicInteger();
    assertEquals(
        0,
        WatchCommand.run(
            new String[] {log.toString(), "--no-state", "--from", "beginning"},
            out,
            err,
            env,
            null,
            () -> stop.incrementAndGet() > 1),
        err.toString());
    env.put("XDG_STATE_HOME", dir.resolve("state").toString());
    stop.set(0);
    String[] args = {log.toString(), "--from", "beginning"};
    assertEquals(0, WatchCommand.run(args, out, err, env, null, () -> stop.incrementAndGet() > 1));
    try (var entries = Files.list(dir.resolve("state/webauditJ/watch"))) {
      Files.writeString(
          entries.filter(p -> p.toString().endsWith(".json")).findFirst().orElseThrow(), "corrupt");
    }
    assertEquals(2, WatchCommand.run(args, out, err, env, null, () -> false));
    stop.set(0);
    assertEquals(
        0,
        WatchCommand.run(
            new String[] {log.toString(), "--reset-state", "--from", "beginning"},
            out,
            err,
            env,
            null,
            () -> stop.incrementAndGet() > 1));
  }

  @Test
  void rejectsGzipAndNonRegularInputs() throws Exception {
    Path gzip = dir.resolve("access.log");
    Files.write(gzip, new byte[] {0x1f, (byte) 0x8b, 0, 0});
    var o = new WatchCommand.Arguments();
    o.inputs.add(gzip);
    assertThrows(IOException.class, () -> new WatchReader(o, s -> {}));
    Path namedGzip = dir.resolve("plain.gz");
    Files.writeString(namedGzip, "plain\n");
    o.inputs = List.of(namedGzip);
    assertThrows(IOException.class, () -> new WatchReader(o, s -> {}));
  }

  @Test
  void malformedUtf8OversizeAndRewriteRecovery() throws Exception {
    Path file = dir.resolve("access.log");
    Files.write(file, new byte[] {(byte) 0xff, 10});
    var o = new WatchCommand.Arguments();
    o.from = "beginning";
    o.maxLine = 4;
    o.inputs.add(file);
    var warnings = new ArrayList<String>();
    try (var r = new WatchReader(o, warnings::add)) {
      Files.writeString(file, "12345\nok\n", StandardOpenOption.APPEND);
      var lines = new ArrayList<String>();
      r.poll((t, p, n) -> lines.add(t));
      assertEquals(List.of("ok"), lines);
      assertEquals(2, warnings.size());
      Files.writeString(file, "new\n".repeat(10));
      r.poll((t, p, n) -> lines.add(t));
      assertEquals(11, lines.size());
      assertTrue(warnings.stream().anyMatch(w -> w.contains("rewrite")));
    }
  }

  @Test
  void stateConfigurationAndTargetValidation() throws Exception {
    Path root = dir.resolve("state");
    var targets = List.of(dir.resolve("access.log").toString());
    try (var s = new WatchStore(root, targets, "a", false)) {
      s.save(Json.map("value", 1));
    }
    try (var s = new WatchStore(root, targets, "b", false)) {
      assertThrows(IOException.class, s::load);
    }
    try (var s = new WatchStore(root, targets, "b", true)) {
      assertNull(s.load());
      s.save(Json.map("value", 2));
    }
    try (var s = new WatchStore(root, targets, "b", false)) {
      assertEquals(2, Json.number(s.load().get("value")));
    }
  }

  @Test
  void engineRestorePreservesRevisionSequenceAndOutcome() {
    var o = new WatchCommand.Arguments();
    var e = new WatchEngine(o, null, s -> {});
    e.observe(LogParser.parse(WatchTest.log("/.env"), "access.log", 1, ""), WatchTest.NOW);
    var created = e.flush(WatchTest.NOW).getFirst();
    var restored = new WatchEngine(o, null, s -> {});
    restored.restore(Json.object(Json.string(e.snapshot())));
    assertTrue(restored.flush(WatchTest.NOW).isEmpty());
    for (int i = 2; i <= 3; i++) {
      var event =
          LogParser.parse(WatchTest.log("/.env").replace("404 12", "200 12"), "access.log", i, "");
      event.time = event.time.plusSeconds(i);
      restored.observe(event, WatchTest.NOW.plusSeconds(i));
    }
    var changed = restored.flush(WatchTest.NOW.plusSeconds(3)).getFirst();
    assertEquals(created.get("incident_id"), changed.get("incident_id"));
    assertEquals("possible_success", changed.get("outcome"));
    assertEquals(2, Json.number(changed.get("sequence")));
    assertEquals(2, Json.number(changed.get("revision")));
  }

  @Test
  void boundedRetentionAndNativeBehavior() {
    var o = new WatchCommand.Arguments();
    o.maxEvents = 40;
    var e = new WatchEngine(o, null, s -> {});
    for (int i = 0; i < 20; i++) {
      var event = LogParser.parse(WatchTest.log("/ordinary"), "access.log", i + 1, "");
      event.time = event.time.plusSeconds(i);
      e.observe(event, WatchTest.NOW.plusSeconds(i));
    }
    assertTrue(
        e.flush(WatchTest.NOW.plusSeconds(20)).stream()
            .anyMatch(v -> ((List<?>) v.get("rule_ids")).contains("WB-404")));
    for (int i = 0; i < 100; i++)
      e.observe(
          LogParser.parse(WatchTest.log("/.env"), "access.log", i + 21, ""),
          WatchTest.NOW.plusSeconds(21));
    assertEquals(40, e.records.size());
    e.flush(WatchTest.NOW.plusSeconds(1000));
    e.flush(WatchTest.NOW.plusSeconds(2000));
    assertTrue(e.records.isEmpty());
  }

  @Test
  void actualWatchLoopRestoresWithoutDuplicates() throws Exception {
    Path log = dir.resolve("access.log");
    Files.writeString(log, WatchTest.log("/.env") + "\n");
    var env = new HashMap<>(System.getenv());
    env.put("XDG_STATE_HOME", dir.resolve("state").toString());
    env.put("XDG_DATA_HOME", dir.resolve("data").toString());
    String[] args = {
      log.toString(), "--from", "beginning", "--format", "jsonl", "--poll-interval", "10ms"
    };
    var out = new StringWriter();
    var err = new StringWriter();
    var polls = new java.util.concurrent.atomic.AtomicInteger();
    assertEquals(
        0,
        WatchCommand.run(args, out, err, env, null, () -> polls.incrementAndGet() > 2),
        err.toString());
    assertTrue(out.toString().contains("incident_created"));
    polls.set(0);
    out.getBuffer().setLength(0);
    assertEquals(
        0,
        WatchCommand.run(args, out, err, env, null, () -> polls.incrementAndGet() > 2),
        err.toString());
    assertEquals("", out.toString());
    Files.writeString(log, WatchTest.log("/.env") + "\n", StandardOpenOption.APPEND);
    polls.set(0);
    assertEquals(
        0,
        WatchCommand.run(args, out, err, env, null, () -> polls.incrementAndGet() > 2),
        err.toString());
    assertTrue(out.toString().contains("incident_updated"));
  }

  @Test
  void processShutdownSavesCheckpointAndReleasesLock() throws Exception {
    Path log = dir.resolve("access.log");
    Files.writeString(log, WatchTest.log("/.env") + "\n");
    for (int i = 0; i < 2; i++) {
      var pb =
          new ProcessBuilder(
              java(),
              "--enable-native-access=ALL-UNNAMED",
              "-cp",
              System.getProperty("java.class.path"),
              Child.class.getName(),
              "watch",
              "watch",
              log.toString(),
              "--from",
              "beginning",
              "--format",
              "jsonl");
      pb.environment().put("XDG_STATE_HOME", dir.resolve("state").toString());
      pb.environment().put("XDG_DATA_HOME", dir.resolve("data").toString());
      Process p = pb.start();
      try {
        assertTrue(p.waitFor(10, TimeUnit.SECONDS));
        String out =
            new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        String err =
            new String(p.getErrorStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(0, p.exitValue(), err);
        if (i == 0) assertTrue(out.contains("incident_created"), err);
        else assertEquals("", out, err);
      } finally {
        p.destroyForcibly();
      }
    }
  }

  @Test
  void geoipIsOptionalAndDoesNotChangeDetection() throws Exception {
    var o = new WatchCommand.Arguments();
    var base = new WatchEngine(o, null, s -> {});
    try (var geo =
        GeoIP.open(
            "src/test/resources/geoip/country.mmdb",
            "src/test/resources/geoip/asn.mmdb",
            null,
            16)) {
      var enriched = new WatchEngine(o, geo, s -> {});
      Event event = LogParser.parse(WatchTest.log("/.env"), "access.log", 1, "");
      event.ip = "8.8.8.8";
      base.observe(event, WatchTest.NOW);
      enriched.observe(event, WatchTest.NOW);
      var plain = base.flush(WatchTest.NOW).getFirst();
      var full = enriched.flush(WatchTest.NOW).getFirst();
      assertNotNull(full.remove("geoip"));
      assertEquals(plain, full);
    }
  }
}
