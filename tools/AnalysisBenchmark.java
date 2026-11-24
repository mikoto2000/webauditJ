package io.github.mikoto2000.webaudit;

import java.lang.management.ManagementFactory;
import java.nio.file.*;
import java.time.*;
import java.util.*;

/** Development-only before/after runner; reports the entire report for parity checking. */
public final class AnalysisBenchmark {
  public static void main(String[] args) throws Exception {
    System.setOut(
        new java.io.PrintStream(System.out, true, java.nio.charset.StandardCharsets.UTF_8));
    var options = new Options();
    options.clock = Clock.fixed(Instant.parse("2026-11-01T00:00:00Z"), ZoneOffset.UTC);
    var bean = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
    boolean supported = bean.isThreadAllocatedMemorySupported();
    if (supported && !bean.isThreadAllocatedMemoryEnabled())
      bean.setThreadAllocatedMemoryEnabled(true);
    long allocated = supported ? bean.getCurrentThreadAllocatedBytes() : 0;
    long start = System.nanoTime();
    var report = Engine.analyze(List.of(Path.of(args[0])), options);
    long elapsed = System.nanoTime() - start;
    long bytes = supported ? bean.getCurrentThreadAllocatedBytes() - allocated : -1;
    System.out.println(
        Json.MAPPER.writeValueAsString(
            Json.map(
                "analysis_seconds",
                elapsed / 1e9,
                "analysis_thread_allocated_bytes",
                bytes,
                "java",
                System.getProperty("java.runtime.version"),
                "os",
                System.getProperty("os.name"),
                "report",
                report)));
  }
}
