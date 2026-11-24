package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
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
        if (bundle) args.addAll(List.of("--report-dir", dir.resolve("bundle-" + verbose).toString()));
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
      assertEquals(content.isEmpty() ? 0 : 1, run(List.of(input.toString(), "--verbose"), new StringWriter(), err));
      assertTrue(err.toString().contains("1/1 files,"), err.toString());
    }
    var err = new StringWriter();
    Path empty = Files.createDirectory(dir.resolve("empty"));
    assertEquals(1, run(List.of(empty.toString(), "--verbose"), new StringWriter(), err));
    assertTrue(err.toString().contains("0/0 files, 0 lines\n"), err.toString());
  }

  private int run(List<String> args, Writer out, Writer err) {
    return Main.run(args.toArray(String[]::new), out, err, Map.of("XDG_DATA_HOME", dir.toString()), null, null);
  }
}
