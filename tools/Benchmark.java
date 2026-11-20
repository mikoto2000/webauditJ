package io.github.mikoto2000.webaudit;

import java.lang.management.ManagementFactory;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/** Development-only runner; use tools/benchmark.py. No network access or DB download. */
public final class Benchmark {
  public static void main(String[] args) throws Exception {
    Path input = Path.of(args[0]);
    var memory = ManagementFactory.getMemoryMXBean();
    var peak = new AtomicLong();
    var sampler = Executors.newSingleThreadScheduledExecutor();
    Runnable sample = () -> peak.accumulateAndGet(memory.getHeapMemoryUsage().getUsed(), Math::max);
    sampler.scheduleAtFixedRate(sample, 0, 10, TimeUnit.MILLISECONDS);
    long start = System.nanoTime(), opened = start;
    GeoIP geo = null;
    try {
      if (args.length == 3) geo = GeoIP.open(args[1], args[2], null, 4096);
      opened = System.nanoTime();
      var options = new Options();
      options.clock = Clock.fixed(Instant.parse("2026-11-01T00:00:00Z"), ZoneOffset.UTC);
      options.geoIP = geo;
      var report = Engine.analyze(List.of(input), options);
      long end = System.nanoTime();
      sample.run();
      var detection = new ArrayList<Map<String, Object>>();
      for (var finding : Json.rows(report.get("findings"))) {
        var row = new LinkedHashMap<String, Object>();
        for (String key :
            List.of("id", "ip", "severity", "attack_score", "count", "outcome", "categories")) {
          row.put(key, finding.get(key));
        }
        detection.add(row);
      }
      String hash = HexFormat.of().formatHex(Core.sha(Json.MAPPER.writeValueAsBytes(detection)));
      System.out.println(
          Json.MAPPER.writeValueAsString(
              Json.map(
                  "java",
                  System.getProperty("java.runtime.version"),
                  "os",
                  System.getProperty("os.name"),
                  "arch",
                  System.getProperty("os.arch"),
                  "cpus",
                  Runtime.getRuntime().availableProcessors(),
                  "input_bytes",
                  Files.size(input),
                  "geoip_enabled",
                  geo != null,
                  "db_open_seconds",
                  (opened - start) / 1e9,
                  "analysis_seconds",
                  (end - opened) / 1e9,
                  "total_seconds",
                  (end - start) / 1e9,
                  "peak_sampled_java_heap_bytes",
                  peak.get(),
                  "parsed",
                  report.get("requests"),
                  "unparsed",
                  report.get("unparsed"),
                  "partial",
                  report.get("partial"),
                  "incidents",
                  Json.rows(report.get("findings")).size(),
                  "detection_sha256",
                  hash,
                  "warnings",
                  report.get("warnings"),
                  "geoip_metrics",
                  geo == null ? null : geo.metrics())));
    } finally {
      sampler.shutdownNow();
      if (geo != null) geo.close();
    }
  }
}
