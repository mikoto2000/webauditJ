package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class MainTest {
  @TempDir Path dir;

  @Test
  void removesIncompleteReportsAndRetainsBothWriteAndCloseFailures() throws Exception {
    Path path = dir.resolve("incomplete.html");
    Files.writeString(path, "partial");
    var file =
        new StringWriter() {
          @Override
          public void close() throws IOException {
            throw new IOException("close failed");
          }
        };
    var error =
        assertThrows(
            IOException.class,
            () ->
                Main.writeAndCloseReport(
                    path,
                    file,
                    out -> {
                      throw new IOException("write failed");
                    }));
    assertEquals("write failed", error.getMessage());
    assertEquals("close failed", error.getSuppressed()[0].getMessage());
    assertFalse(Files.exists(path));
    Files.writeString(path, "complete but close failed");
    assertThrows(IOException.class, () -> Main.writeAndCloseReport(path, file, out -> {}));
    assertFalse(Files.exists(path));
  }

  @Test
  void completedReportSurvivesSummaryOutputFailure() throws Exception {
    Path input = dir.resolve("a.log"), output = dir.resolve("report.html");
    Files.writeString(input, CorrelatorTest.event(0, 404).raw);
    Writer broken =
        new Writer() {
          public void write(char[] c, int a, int b) throws IOException {
            throw new IOException("broken stdout");
          }

          public void flush() {}

          public void close() {}
        };
    assertEquals(
        1,
        Main.run(
            new String[] {input.toString(), "-o", output.toString()},
            broken,
            new StringWriter(),
            Map.of("XDG_DATA_HOME", dir.toString()),
            null,
            null));
    assertTrue(Files.readString(output).contains("</html>"));
  }

  @Test
  void validatesGoTimezoneNamesIncludingLocalAndRejectsOffsetAliases() throws Exception {
    Path input = dir.resolve("zone.log");
    Files.writeString(input, CorrelatorTest.event(0, 404).raw);
    assertEquals(0, run(input.toString(), "--error-timezone", "Local"));
    assertEquals(2, run(input.toString(), "--error-timezone", "Z"));
    assertEquals(2, run(input.toString(), "--error-timezone", "+09:00"));
  }

  int run(String... args) {
    return Main.run(
        args,
        new StringWriter(),
        new StringWriter(),
        Map.of("LOCALAPPDATA", dir.toString(), "HOME", dir.toString()),
        dir.resolve("legacy"),
        null);
  }

  @Test
  void supportsInterspersedOptionsFormatsAndNeverOverwrites() throws Exception {
    Path input = dir.resolve("a.log"), output = dir.resolve("report.json");
    Files.writeString(input, CorrelatorTest.event(0, 404).raw);
    assertEquals(0, run(input.toString(), "--format", "json", "-o", output.toString()));
    assertEquals("webaudit/2", Json.object(Files.readString(output)).get("schema"));
    assertEquals(2, run(input.toString(), "-o", output.toString()));
    assertEquals(0, run("--version"));
    assertEquals(0, run("--help"));
    assertEquals(2, run());
    assertEquals(2, run(input.toString(), "--max-keys", "0"));
    assertEquals(2, run(input.toString(), "--format", "xml"));
  }

  @Test
  void returnsPartialAndExplicitDbErrors() throws Exception {
    Path input = dir.resolve("bad.log");
    Files.writeString(input, "garbage\n");
    assertEquals(1, run(input.toString()));
    assertEquals(
        2, run(input.toString(), "--geoip-country", dir.resolve("missing.mmdb").toString()));
  }

  @Test
  void managesSyntheticDatabasesAndReportsStatusWithoutProviderCalls() throws Exception {
    var env = Map.of("XDG_DATA_HOME", dir.toString());
    var source = new DatabaseManagerTest.Fake();
    var out = new StringWriter();
    assertEquals(
        0,
        Main.run(new String[] {"geoip", "download"}, out, new StringWriter(), env, null, source));
    assertEquals(2, source.fetch);
    assertEquals(
        0,
        Main.run(
            new String[] {"geoip", "status"},
            new StringWriter(),
            new StringWriter(),
            env,
            null,
            source));
    assertEquals(2, source.latest);
    assertTrue(Files.exists(dir.resolve("webauditJ/geoip/metadata.json")));
  }
}
