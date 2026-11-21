package io.github.mikoto2000.webaudit;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

final class WatchHooks implements AutoCloseable {
  record Hook(String executable, List<String> args) {
    Hook {
      args = List.copyOf(args);
    }

    String id() {
      return "hook-" + WatchEngine.hash(Json.string(List.of(executable, args))).substring(0, 32);
    }
  }

  final WatchCommand.Arguments o;
  final Consumer<String> warn;
  final ThreadPoolExecutor pool;
  final Map<String, Long> history = new HashMap<>();
  final Set<Process> active = ConcurrentHashMap.newKeySet();
  volatile boolean closed;
  long dropped;

  WatchHooks(WatchCommand.Arguments o, Consumer<String> warn, Map<String, Object> saved) {
    this.o = o;
    this.warn = warn;
    if (saved != null) {
      if (saved.size() > 32000)
        throw new IllegalArgumentException("notification history exceeds limit");
      saved.forEach((k, v) -> {
        if (!(v instanceof Number) || Json.number(v) < 1)
          throw new IllegalArgumentException("invalid notification history");
        history.put(k, Json.number(v));
      });
    }
    pool =
        new ThreadPoolExecutor(
            o.concurrency,
            o.concurrency,
            0,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(o.queue),
            Thread.ofPlatform().daemon().name("watch-hook-", 0).factory(),
            new ThreadPoolExecutor.AbortPolicy());
  }

  void dispatch(Map<String, Object> event, boolean significant) {
    String kind = Json.string(event.get("event_type"));
    if (closed
        || !significant
        || kind.equals("incident_closed")
        || Core.weight(Json.string(event.get("severity"))) < Core.weight(o.severity)) return;
    if (o.events.equals("created") && !kind.equals("incident_created")
        || o.events.equals("updated") && !kind.equals("incident_updated")) return;
    for (var hook : o.hooks) {
      String key = hook.id() + "/" + event.get("incident_id");
      long revision = Json.number(event.get("revision"));
      if (history.getOrDefault(key, 0L) >= revision) continue;
      var payload = new LinkedHashMap<>(event);
      payload.put("hook_id", hook.id());
      payload.put(
          "notification_id",
          "notification-" + WatchEngine.hash(key + "/" + revision).substring(0, 32));
      byte[] bytes = (Json.string(payload) + "\n").getBytes(StandardCharsets.UTF_8);
      if (bytes.length > 65536) {
        warn.accept("hook payload exceeds 64 KiB");
        continue;
      }
      try {
        pool.execute(() -> execute(hook, bytes));
        history.put(key, revision);
      } catch (RejectedExecutionException ex) {
        dropped++;
        warn.accept("hook queue full; notifications dropped");
      }
    }
  }

  void prune(Set<String> ids) {
    history.keySet().removeIf(key -> !ids.contains(key.substring(key.indexOf('/') + 1)));
  }

  Map<String, Object> snapshot() {
    return new TreeMap<>(history);
  }

  void execute(Hook hook, byte[] bytes) {
    Process p = null;
    java.lang.foreign.MemorySegment job = null;
    var streams = new ArrayList<Thread>();
    try {
      if (closed || Thread.currentThread().isInterrupted()) return;
      var command = new ArrayList<String>();
      command.add(hook.executable);
      command.addAll(hook.args);
      String javaExecutable =
          java.nio.file.Path.of(
                  System.getProperty("java.home"),
                  "bin",
                  Main.os().equals("windows") ? "java.exe" : "java")
              .toString();
      long deadline = System.nanoTime() + o.timeout().toNanos();
      p =
          new ProcessBuilder(
                  javaExecutable,
                  "--enable-native-access=ALL-UNNAMED",
                  "-cp",
                  System.getProperty("java.class.path"),
                  WatchHookChild.class.getName())
              .start();
      active.add(p);
      Process child = p;
      if (closed) throw new IOException("hook dispatcher stopped");
      if (Main.os().equals("windows")) job = WatchNative.job(p);
      var ready =
          new FutureTask<Boolean>(() -> {
            byte[] marker = child.getInputStream().readNBytes(6);
            return Arrays.equals(marker, "READY\n".getBytes(StandardCharsets.US_ASCII));
          });
      streams.add(Thread.ofVirtual().start(ready));
      if (!ready.get(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS))
        throw new IOException("hook containment helper failed");
      byte[] config =
          Json.string(
                  Json.map(
                      "command", command, "payload", Base64.getEncoder().encodeToString(bytes)))
              .getBytes(StandardCharsets.UTF_8);
      // Drain both pipes concurrently; never redisplay untrusted child output.
      streams.add(Thread.ofVirtual().start(() -> drain(child.getInputStream())));
      streams.add(Thread.ofVirtual().start(() -> drain(child.getErrorStream())));
      streams.add(
          Thread.ofVirtual()
              .start(() -> {
                try (var stdin = child.getOutputStream()) {
                  stdin.write(config);
                } catch (IOException ignored) {
                }
              }));
      if (!p.waitFor(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS))
        warn.accept("hook timed out");
      else if (p.exitValue() != 0) warn.accept("hook failed with exit code " + p.exitValue());
    } catch (IOException | ExecutionException ex) {
      warn.accept("hook could not start or containment failed: " + hook.executable);
    } catch (TimeoutException ex) {
      warn.accept("hook timed out");
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
    } finally {
      if (p != null) {
        try {
          if (job != null) WatchNative.closeHandle(job);
          else if (!Main.os().equals("windows")) WatchNative.killGroup(p.pid());
        } catch (IOException ex) {
          warn.accept("hook process containment cleanup failed");
        }
        p.descendants().forEach(ProcessHandle::destroyForcibly);
        p.destroyForcibly();
        active.remove(p);
        try {
          p.getInputStream().close();
        } catch (IOException ignored) {
        }
        try {
          p.getErrorStream().close();
        } catch (IOException ignored) {
        }
        try {
          p.getOutputStream().close();
        } catch (IOException ignored) {
        }
      }
      for (var t : streams) t.interrupt();
    }
  }

  static void drain(InputStream input) {
    try (input) {
      byte[] b = new byte[8192];
      while (input.read(b) != -1) {}
    } catch (IOException ignored) {
    }
  }

  public synchronized void close() {
    if (closed) return;
    closed = true;
    pool.shutdownNow();
    for (var p : active) {
      p.descendants().forEach(ProcessHandle::destroyForcibly);
      p.destroyForcibly();
    }
    try {
      if (!pool.awaitTermination(3, TimeUnit.SECONDS))
        warn.accept("hook worker shutdown timed out");
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
    }
    if (dropped > 0) warn.accept("hook notifications dropped: " + dropped);
  }
}
