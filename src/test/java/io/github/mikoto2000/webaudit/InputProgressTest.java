package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class InputProgressTest {
  @TempDir Path dir;

  @Test
  void verboseProgressStaysOnStderrIncludingBundles() throws Exception {
    Path input = dir.resolve("a.log");
    Files.writeString(input, CorrelatorTest.event(0, 404).raw + "\n");
    for (boolean bundle : List.of(false, true)) {
      for (boolean verbose : List.of(false, true)) {
        var args = new ArrayList<>(List.of(input.toString()));
        if (bundle)
          args.addAll(List.of("--report-dir", dir.resolve("bundle-" + verbose).toString()));
        else args.addAll(List.of("--format", "json"));
        if (verbose) args.add("--verbose");
        var out = new StringWriter();
        var err = new StringWriter();
        assertEquals(0, run(args, out, err), err.toString());
        assertEquals(verbose, err.toString().contains("Input files ["));
        if (verbose) {
          assertTrue(err.toString().contains("0/1 files, 0 lines"), err.toString());
          assertTrue(err.toString().contains("1/1 files, 1 lines\n"), err.toString());
        }
        if (!bundle) assertEquals("webaudit/2", Json.object(out.toString()).get("schema"));
      }
    }
  }

  @Test
  void partialAndEmptyInputStillFinishProgress() throws Exception {
    Path input = dir.resolve("a.log");
    for (String content : List.of("", "invalid\n")) {
      Files.writeString(input, content);
      var err = new StringWriter();
      assertEquals(
          content.isEmpty() ? 0 : 1,
          run(List.of(input.toString(), "--verbose"), new StringWriter(), err));
      assertTrue(err.toString().contains("1/1 files,"), err.toString());
    }
    var err = new StringWriter();
    Path empty = Files.createDirectory(dir.resolve("empty"));
    assertEquals(1, run(List.of(empty.toString(), "--verbose"), new StringWriter(), err));
    assertTrue(err.toString().contains("0/0 files, 0 lines\n"), err.toString());
  }

  private int run(List<String> args, Writer out, Writer err) {
    return Main.run(
        args.toArray(String[]::new), out, err, Map.of("XDG_DATA_HOME", dir.toString()), null, null);
  }

  @Test
  void updatesDuringSingleFileAndThrottlesAndFlushes() {
    class FlushedWriter extends StringWriter {
      int flushes;

      @Override
      public void flush() {
        flushes++;
      }
    }
    var out = new FlushedWriter();
    long[] now = {1};
    var display = new InputProgressDisplay(out, () -> now[0]);
    display.accept(new InputProgress(0, 1, 0));
    int initial = out.toString().length();
    display.accept(new InputProgress(0, 1, 1));
    assertEquals(initial, out.toString().length());
    now[0] += 100_000_000L;
    display.accept(new InputProgress(0, 1, 2));
    assertTrue(out.toString().contains("0/1 files, 2 lines"));
    display.accept(new InputProgress(1, 1, 2));
    assertTrue(out.toString().endsWith("1/1 files, 2 lines\n"));
    assertEquals(3, out.flushes);
  }

  @Test
  void streamsGzipAndCountsDuplicateAndFailedFiles() throws Exception {
    Path input = dir.resolve("a.log.gz");
    try (var gz = new GZIPOutputStream(Files.newOutputStream(input))) {
      gz.write("\ninvalid\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
    Files.copy(input, dir.resolve("b.log.gz"));
    Files.write(dir.resolve("c.log.gz"), new byte[] {0x1f, (byte) 0x8b});
    var updates = new ArrayList<InputProgress>();
    var options = new Options();
    options.deduplicateFiles = true;
    options.progress = updates::add;
    var report = Engine.analyze(List.of(dir), options);
    var files = Json.rows(report.get("files"));
    assertTrue(Json.bool(report.get("partial")));
    assertEquals(3, files.size());
    assertFalse(Json.string(files.get(1).get("duplicate_of")).isEmpty());
    assertFalse(Json.string(files.get(2).get("error")).isEmpty());
    assertEquals(new InputProgress(0, 3, 0), updates.getFirst());
    assertEquals(new InputProgress(0, 3, 1), updates.get(1));
    assertEquals(new InputProgress(3, 3, 2), updates.getLast());
  }
}
