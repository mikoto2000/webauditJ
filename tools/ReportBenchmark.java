package io.github.mikoto2000.webaudit;

import java.lang.management.ManagementFactory;
import java.lang.ref.Reference;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/** Synthetic development measurement. Run conditions sequentially, not concurrently. */
public final class ReportBenchmark {
  public static void main(String[] args) throws Exception {
    int count = Integer.parseInt(args[0]);
    String mode = args[1];
    boolean mixed = Boolean.parseBoolean(args[2]);
    long cap = Long.parseLong(args[3]);
    if (count < 1 || !Set.of("analysis", "bundle").contains(mode) || cap < 1)
      throw new IllegalArgumentException("invalid benchmark arguments");
    Path owned = Files.createTempDirectory("webauditJ-report-benchmark-").toRealPath();
    try {
      Path input = owned.resolve("access.log"), output = owned.resolve("report");
      var formatter = DateTimeFormatter.ofPattern("dd/MMM/uuuu:HH:mm:ss Z", Locale.ENGLISH);
      var start = OffsetDateTime.parse("2026-11-01T00:00:00Z");
      try (var writer = Files.newBufferedWriter(input, StandardCharsets.UTF_8)) {
        for (int i = 0; i < count; i++) {
          String uri = mixed && i % 5 == 0 ? "/.env" : "/api/items/" + (i % 32);
          writer.write(
              "192.0.2."
                  + (i % 16 + 1)
                  + " - - ["
                  + formatter.format(start.plusSeconds(i))
                  + "] \"GET "
                  + uri
                  + " HTTP/1.1\" "
                  + (mixed && i % 5 == 0 ? 404 : 200)
                  + " 100 \"-\" \"Browser\"\n");
        }
      }
      System.gc();
      var memory = ManagementFactory.getMemoryMXBean();
      var peak = new AtomicLong();
      var peakSpool = new AtomicLong();
      var sampler = Executors.newSingleThreadScheduledExecutor();
      Runnable sample =
          () -> {
            peak.accumulateAndGet(memory.getHeapMemoryUsage().getUsed(), Math::max);
            if (Files.isDirectory(output))
              try (var files = Files.list(output)) {
                for (Path file :
                    files.filter(p -> p.getFileName().toString().startsWith(".requests-")).toList())
                  try {
                    peakSpool.accumulateAndGet(Files.size(file), Math::max);
                  } catch (Exception ignored) {
                  }
              } catch (Exception ignored) {
              }
          };
      sampler.scheduleAtFixedRate(sample, 0, 10, TimeUnit.MILLISECONDS);
      long began = System.nanoTime();
      Map<String, Object> report;
      long spool = 0;
      boolean complete, evidenceComplete = false;
      List<?> warnings;
      try {
        var options = new Options();
        if (mode.equals("analysis")) {
          report = Engine.analyze(List.of(input), options);
          complete = !Json.bool(report.get("partial"));
          warnings = (List<?>) report.get("warnings");
        } else {
          var bundle = new BundleOptions();
          bundle.language = "en";
          bundle.maxSpoolBytes = cap;
          bundle.maxOutputBytes = 256L << 20;
          report = Bundle.generate(List.of(input), output, options, bundle);
          complete = Json.bool(report.get("complete"));
          evidenceComplete = Json.bool(report.get("evidence_complete"));
          spool = Json.number(Json.obj(report.get("evidence")).get("spool_bytes"));
          warnings = (List<?>) Json.obj(report.get("analysis")).get("warnings");
        }
      } finally {
        sample.run();
        sampler.shutdownNow();
        sampler.awaitTermination(5, TimeUnit.SECONDS);
      }
      double seconds = (System.nanoTime() - began) / 1e9;
      long artifacts = 0;
      if (Files.isDirectory(output))
        try (var files = Files.walk(output)) {
          for (Path file : files.filter(Files::isRegularFile).toList())
            artifacts += Files.size(file);
        }
      long committed = memory.getHeapMemoryUsage().getCommitted();
      System.gc();
      long retained = memory.getHeapMemoryUsage().getUsed();
      long parsed =
          Json.number(
              mode.equals("analysis")
                  ? report.get("requests")
                  : Json.obj(report.get("analysis")).get("requests"));
      System.out.println(
          Json.MAPPER.writeValueAsString(
              Json.map(
                  "synthetic",
                  true,
                  "java",
                  System.getProperty("java.runtime.version"),
                  "os",
                  System.getProperty("os.name"),
                  "arch",
                  System.getProperty("os.arch"),
                  "cpus",
                  Runtime.getRuntime().availableProcessors(),
                  "mode",
                  mode,
                  "mixed",
                  mixed,
                  "lines",
                  count,
                  "input_bytes",
                  Files.size(input),
                  "parsed",
                  parsed,
                  "seconds",
                  seconds,
                  "requests_per_second",
                  parsed / seconds,
                  "sample_interval_ms",
                  10,
                  "peak_sampled_java_heap_bytes",
                  peak.get(),
                  "post_gc_heap_used_bytes",
                  retained,
                  "heap_committed_bytes",
                  committed,
                  "max_heap_bytes",
                  Runtime.getRuntime().maxMemory(),
                  "peak_sampled_spool_bytes",
                  peakSpool.get(),
                  "spool_bytes",
                  spool,
                  "spool_limit_bytes",
                  cap,
                  "final_artifact_bytes",
                  artifacts,
                  "disk_upper_bound_bytes",
                  artifacts + spool,
                  "complete",
                  complete,
                  "evidence_complete",
                  evidenceComplete,
                  "warnings",
                  warnings)));
      Reference.reachabilityFence(report);
    } finally {
      if (!owned.isAbsolute()
          || !owned.getFileName().toString().startsWith("webauditJ-report-benchmark-"))
        throw new IllegalStateException("Unexpected temporary root");
      try (var paths = Files.walk(owned)) {
        for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
          if (!path.toAbsolutePath().normalize().startsWith(owned))
            throw new IllegalStateException("Unexpected cleanup path");
          Files.delete(path);
        }
      }
    }
  }
}
