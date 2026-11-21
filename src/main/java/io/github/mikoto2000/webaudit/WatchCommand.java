package io.github.mikoto2000.webaudit;

import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.*;
import picocli.CommandLine;

final class WatchCommand {
  @CommandLine.Command(
      name = "webauditJ watch",
      showDefaultValues = true,
      description = "Watch local access logs. Ctrl+C saves the checkpoint and stops hooks.")
  static final class Arguments {
    @CommandLine.Parameters(arity = "0..*", paramLabel = "INPUT")
    List<Path> inputs = new ArrayList<>();

    @CommandLine.Option(
        names = {"--help", "-h", "-help"},
        description = "Show this help")
    boolean help;

    @CommandLine.Option(
        names = {"--from", "-from"},
        description = "beginning or end; a saved checkpoint takes precedence")
    String from = "end";

    @CommandLine.Option(
        names = {"--format", "-format"},
        description = "text or jsonl")
    String format = "text";

    @CommandLine.Option(
        names = {"--include", "-include"},
        description = "Directory filename glob (nonrecursive)")
    String include = "";

    @CommandLine.Option(
        names = {"--exclude", "-exclude"},
        description = "Exclude filename glob")
    String exclude = "";

    @CommandLine.Option(
        names = {"--max-files", "-max-files"},
        description = "Open file limit (1..4096)")
    int maxFiles = 64;

    @CommandLine.Option(
        names = {"--max-line-bytes", "-max-line-bytes"},
        description = "Partial line limit (1..16777216 bytes)")
    int maxLine = 65536;

    @CommandLine.Option(
        names = {"--max-events", "-max-events"},
        description = "Retained event limit (1..100000)")
    int maxEvents = 8192;

    @CommandLine.Option(
        names = {"--poll-interval", "-poll-interval"},
        description = "Polling duration (10ms..1m)")
    String interval = "250ms";

    @CommandLine.Option(
        names = {"--allowed-lateness", "-allowed-lateness"},
        description = "Maximum event lateness (greater than zero, at most 1h)")
    String allowedLateness = "30s";

    @CommandLine.Option(
        names = {"--retention", "-retention"},
        description = "Retention horizon (5m + allowed lateness, at most 24h)")
    String retentionTime = "15m";

    @CommandLine.Option(
        names = {"--no-state", "-no-state"},
        description = "Disable checkpoint reads and writes")
    boolean noState;

    @CommandLine.Option(
        names = {"--reset-state", "-reset-state"},
        description = "Ignore saved checkpoint and start from --from")
    boolean resetState;

    @CommandLine.Option(
        names = {"--geoip-country", "-geoip-country"},
        description = "Local Country MMDB override")
    String country = "";

    @CommandLine.Option(
        names = {"--geoip-asn", "-geoip-asn"},
        description = "Local ASN MMDB override")
    String asn = "";

    @CommandLine.Option(
        names = {"--on-detect-severity", "-on-detect-severity"},
        description = "Minimum hook severity: low, medium, high, critical")
    String severity = "high";

    @CommandLine.Option(
        names = {"--on-detect-event", "-on-detect-event"},
        description = "Hook event filter: created, updated, all (significant changes only)")
    String events = "created";

    @CommandLine.Option(
        names = {"--hook-timeout", "-hook-timeout"},
        description = "Timeout including helper startup (1ms..1h)")
    String hookTimeout = "10s";

    @CommandLine.Option(
        names = {"--hook-concurrency", "-hook-concurrency"},
        description = "Concurrent hooks (1..32)")
    int concurrency = 1;

    @CommandLine.Option(
        names = {"--hook-queue-size", "-hook-queue-size"},
        description = "Pending FIFO notifications (1..4096)")
    int queue = 128;

    final List<WatchHooks.Hook> hooks = new ArrayList<>();

    @CommandLine.Option(
        names = {"--on-detect", "-on-detect"},
        description = "Hook executable; repeat for multiple hooks (maximum 16)")
    void hook(String value) {
      if (hooks.size() >= 16 || value.isEmpty())
        throw new IllegalArgumentException("maximum 16 nonempty hooks");
      hooks.add(new WatchHooks.Hook(value, List.of()));
    }

    @CommandLine.Option(
        names = {"--on-detect-arg", "-on-detect-arg"},
        description = "Literal argument for the preceding hook (maximum 64)")
    void arg(String value) {
      if (hooks.isEmpty()) throw new IllegalArgumentException("requires preceding --on-detect");
      var h = hooks.removeLast();
      var args = new ArrayList<>(h.args());
      if (args.size() >= 64) throw new IllegalArgumentException("maximum 64 hook arguments");
      args.add(value);
      hooks.add(new WatchHooks.Hook(h.executable(), args));
    }

    Duration lateness() {
      return duration(allowedLateness);
    }

    Duration retention() {
      return duration(retentionTime);
    }

    Duration timeout() {
      return duration(hookTimeout);
    }

    void validate() {
      if (inputs.isEmpty()
          || !Set.of("end", "beginning").contains(from)
          || !Set.of("text", "jsonl").contains(format)
          || maxFiles < 1
          || maxFiles > 4096
          || maxLine < 1
          || maxLine > (16 << 20)
          || maxEvents < 1
          || maxEvents > 100000
          || duration(interval).compareTo(Duration.ofMillis(10)) < 0
          || duration(interval).compareTo(Duration.ofMinutes(1)) > 0
          || lateness().isZero()
          || lateness().isNegative()
          || lateness().compareTo(Duration.ofHours(1)) > 0
          || retention().compareTo(Duration.ofMinutes(5).plus(lateness())) < 0
          || retention().compareTo(Duration.ofHours(24)) > 0
          || timeout().compareTo(Duration.ofMillis(1)) < 0
          || timeout().compareTo(Duration.ofHours(1)) > 0
          || concurrency < 1
          || concurrency > 32
          || queue < 1
          || queue > 4096
          || !Set.of("low", "medium", "high", "critical").contains(severity)
          || !Set.of("created", "updated", "all").contains(events))
        throw new IllegalArgumentException("invalid watch options (see watch --help)");
    }
  }

  static Duration duration(String value) {
    // Go duration notation, including composite values such as 1m30s.
    var matcher =
        java.util.regex.Pattern.compile("([0-9]+(?:\\.[0-9]+)?)(ns|us|µs|μs|ms|s|m|h)")
            .matcher(value);
    java.math.BigDecimal nanos = java.math.BigDecimal.ZERO;
    int end = 0;
    while (matcher.find()) {
      if (matcher.start() != end) throw new IllegalArgumentException("invalid duration: " + value);
      long scale =
          switch (matcher.group(2)) {
            case "ns" -> 1;
            case "us", "µs", "μs" -> 1000;
            case "ms" -> 1000000;
            case "s" -> 1000000000;
            case "m" -> 60000000000L;
            default -> 3600000000000L;
          };
      nanos =
          nanos.add(
              new java.math.BigDecimal(matcher.group(1))
                  .multiply(java.math.BigDecimal.valueOf(scale)));
      end = matcher.end();
    }
    if (end != value.length() || end == 0)
      throw new IllegalArgumentException("invalid duration: " + value);
    return Duration.ofNanos(nanos.longValueExact());
  }

  static final class Diagnostics implements Consumer<String> {
    final Writer err;
    Instant window = Instant.now();
    final Set<String> seen = new HashSet<>();
    long suppressed;

    Diagnostics(Writer err) {
      this.err = err;
    }

    public synchronized void accept(String text) {
      try {
        if (Instant.now().isAfter(window.plusSeconds(5))) {
          finish();
          seen.clear();
          window = Instant.now();
        }
        if (seen.size() >= 10 || !seen.add(text)) {
          suppressed++;
          return;
        }
        err.write(Reports.terminal(text) + "\n");
        err.flush();
      } catch (IOException ex) {
        throw new UncheckedIOException(ex);
      }
    }

    synchronized void finish() throws IOException {
      if (suppressed > 0) {
        err.write(suppressed + " repeated/excess diagnostics suppressed\n");
        suppressed = 0;
        err.flush();
      }
    }
  }

  static int run(String[] args, Writer out, Writer err, Map<String, String> env, Path legacy) {
    return run(args, out, err, env, legacy, () -> false);
  }

  static int run(
      String[] args,
      Writer out,
      Writer err,
      Map<String, String> env,
      Path legacy,
      BooleanSupplier stop) {
    var a = new Arguments();
    var command =
        new CommandLine(a).setExpandAtFiles(false).setPosixClusteredShortOptionsAllowed(false);
    var warn = new Diagnostics(err);
    try {
      try {
        command.parseArgs(args);
        if (a.help) {
          command.usage(new PrintWriter(err, true));
          return 0;
        }
        a.validate();
      } catch (RuntimeException ex) {
        warn.accept(Objects.toString(ex.getMessage(), "invalid arguments"));
        return 2;
      }
      Path geoDir = null;
      try {
        geoDir = Path.of(GeoPaths.resolve(Main.os(), env));
      } catch (IllegalArgumentException ex) {
        warn.accept(ex.getMessage());
      }
      ManagedGeoIP.Opened opened;
      try {
        opened = ManagedGeoIP.open(a.country, a.asn, geoDir, legacy, 4096);
      } catch (IOException ex) {
        warn.accept(ex.getMessage());
        return 2;
      }
      try (var geo = opened.geo()) {
        opened.warnings().forEach(warn);
        WatchReader reader;
        WatchStore store = null;
        WatchEngine engine = new WatchEngine(a, geo, warn);
        Map<String, Object> state = null;
        try {
          reader = new WatchReader(a, warn);
        } catch (IOException | RuntimeException ex) {
          warn.accept(ex.getMessage());
          return 2;
        }
        try (reader) {
          try {
            if (!a.noState) {
              String key =
                  WatchEngine.hash(
                      Json.string(
                          List.of(
                              Engine.RULES_VERSION,
                              a.lateness().toString(),
                              a.retention().toString(),
                              a.maxEvents,
                              a.maxLine,
                              a.include,
                              a.exclude)));
              store = new WatchStore(WatchStore.directory(env), reader.targets, key, a.resetState);
              state = store.load();
              if (state != null) {
                engine.restore(Json.obj(state.get("engine")));
                reader.restore(Json.obj(state.get("reader")));
              }
            }
          } catch (IOException | RuntimeException ex) {
            if (store != null) store.close();
            warn.accept(
                Objects.toString(ex.getMessage(), "invalid watch state") + "; use --reset-state");
            return 2;
          }
          final WatchStore checkpoint = store;
          try (checkpoint;
              var hooks =
                  new WatchHooks(
                      a, warn, state == null ? null : Json.obj(state.get("notifications")))) {
            Object gate = new Object();
            AtomicBoolean stopping = new AtomicBoolean();
            AtomicBoolean finished = new AtomicBoolean();
            Runnable save =
                () -> {
                  if (checkpoint != null)
                    try {
                      checkpoint.save(
                          Json.map(
                              "engine",
                              engine.snapshot(),
                              "reader",
                              reader.snapshot(),
                              "notifications",
                              hooks.snapshot()));
                    } catch (IOException ex) {
                      throw new UncheckedIOException(ex);
                    }
                };
            Thread shutdown =
                new Thread(
                    () -> {
                      stopping.set(true);
                      synchronized (gate) {
                        if (!finished.getAndSet(true)) {
                          try {
                            save.run();
                            out.flush();
                          } catch (RuntimeException | IOException ex) {
                            warn.accept("watch shutdown checkpoint failed");
                          } finally {
                            hooks.close();
                          }
                        }
                      }
                    },
                    "watch-shutdown");
            Runtime.getRuntime().addShutdownHook(shutdown);
            try {
              warn.accept("WebAuditJ Watch: monitoring " + reader.targets);
              Instant lastSave = Instant.now();
              while (!stopping.get()
                  && !stop.getAsBoolean()
                  && !Thread.currentThread().isInterrupted()) {
                synchronized (gate) {
                  reader.poll((text, file, line) -> {
                    try {
                      engine.observe(LogParser.parse(text, file, line, ""), Instant.now());
                    } catch (IllegalArgumentException ex) {
                      warn.accept("unparsed access log line");
                    }
                  });
                  for (var event : engine.flush(Instant.now())) {
                    if (a.format.equals("jsonl")) out.write(Json.string(event) + "\n");
                    else
                      out.write(
                          Reports.terminal(
                                  "["
                                      + event.get("updated_at")
                                      + "] "
                                      + event.get("event_type")
                                      + " "
                                      + event.get("severity")
                                      + " "
                                      + event.get("incident_id")
                                      + " revision="
                                      + event.get("revision")
                                      + " IP="
                                      + event.get("source_ips")
                                      + " outcome="
                                      + event.get("outcome")
                                      + " count="
                                      + event.get("count"))
                              + "\n");
                    out.flush();
                    hooks.dispatch(
                        event, engine.notifications.contains(Json.string(event.get("event_id"))));
                  }
                  hooks.prune(engine.incidents.keySet());
                  if (Instant.now().isAfter(lastSave.plusSeconds(1))) {
                    save.run();
                    lastSave = Instant.now();
                  }
                }
                try {
                  Thread.sleep(duration(a.interval));
                } catch (InterruptedException ex) {
                  Thread.currentThread().interrupt();
                  break;
                }
              }
              Thread.interrupted(); // An interrupted FileChannel write would close the checkpoint.
              synchronized (gate) {
                if (!finished.getAndSet(true)) {
                  save.run();
                  out.flush();
                  hooks.close();
                }
              }
              return 0;
            } finally {
              try {
                Runtime.getRuntime().removeShutdownHook(shutdown);
              } catch (IllegalStateException ignored) {
              }
            }
          }
        }
      }
    } catch (IOException | RuntimeException ex) {
      warn.accept(Objects.toString(ex.getMessage(), ex.getClass().getSimpleName()));
      return 1;
    } finally {
      try {
        warn.finish();
      } catch (IOException ignored) {
      }
    }
  }
}
