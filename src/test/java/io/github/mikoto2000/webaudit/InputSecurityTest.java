package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class InputSecurityTest {
  @TempDir Path dir;

  @Test
  void preservesGoUnicodeWhitespaceAndDoesNotSkipRecordSeparators() throws Exception {
    Path p = dir.resolve("whitespace.log");
    Files.writeString(p, "\u00a0\n\u0085\n\u001c\n" + CorrelatorTest.event(0, 404).raw);
    var report = Engine.analyze(List.of(p), new Options());
    assertEquals(1, Json.number(report.get("requests")));
    assertEquals(1, Json.number(report.get("unparsed")));
    assertTrue(Reports.csvSafe("\u0085=1+1").startsWith("'"));
  }

  static byte[] gzip(byte[] data) throws Exception {
    var out = new ByteArrayOutputStream();
    try (var gzip = new GZIPOutputStream(out)) {
      gzip.write(data);
    }
    return out.toByteArray();
  }

  @Test
  void acceptsConcatenatedGzipButReportsTrailingGarbageAndCrcCorruption() throws Exception {
    String line = CorrelatorTest.event(0, 404).raw + "\n";
    byte[] packed = gzip(line.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    Path p = dir.resolve("a.log");
    var joined = new ByteArrayOutputStream();
    joined.write(packed);
    joined.write(packed);
    Files.write(p, joined.toByteArray());
    assertEquals(2, Json.number(Engine.analyze(List.of(p), new Options()).get("requests")));
    joined.reset();
    joined.write(packed);
    joined.write("trailing junk".getBytes());
    Files.write(p, joined.toByteArray());
    assertTrue(
        Json.bool(Engine.analyze(List.of(p), new Options()).get("partial")),
        "trailing gzip garbage must not be silently ignored");
    packed[packed.length - 5] ^= 0xff;
    Files.write(p, packed);
    assertTrue(Json.bool(Engine.analyze(List.of(p), new Options()).get("partial")));
  }

  @Test
  void boundsDecompressionAndRejectsUtf8WithoutLosingFollowingLines() throws Exception {
    String line = CorrelatorTest.event(0, 404).raw + "\n";
    Path p = dir.resolve("a.gz");
    Files.write(p, gzip(line.repeat(100).getBytes()));
    var o = new Options();
    o.maxFileBytes = 500;
    assertTrue(Json.bool(Engine.analyze(List.of(p), o).get("partial")));
    var data = new ByteArrayOutputStream();
    data.write(0xff);
    data.write('\n');
    data.write(line.getBytes());
    Files.write(p, data.toByteArray());
    var r = Engine.analyze(List.of(p), new Options());
    assertEquals(1, Json.number(r.get("requests")));
    assertEquals(1, Json.number(r.get("unparsed")));
  }

  @Test
  void appliesExplicitTimezoneAndRejectsJsonTimeAmbiguity() throws Exception {
    String line =
        "2026/11/01 00:00:00 [error] 12#12: open() failed, client: 192.0.2.1, server: _, request:"
            + " \"GET /.env HTTP/1.1\"";
    Path p = dir.resolve("error.log");
    Files.writeString(p, line);
    var o = new Options();
    assertNull(Engine.analyze(List.of(p), o).get("first"));
    o.errorTimezone = "Asia/Tokyo";
    assertEquals("2026-11-01T00:00:00+09:00", Engine.analyze(List.of(p), o).get("first"));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            LogParser.parse(
                "{\"remote_addr\":\"8.8.8.8\",\"time_local\":\"01/Nov/2026:00:00:00"
                    + " +0000\",\"time_iso8601\":\"2026-11-01T00:00:00Z\",\"request\":\"GET /"
                    + " HTTP/1.1\"}",
                "x",
                1,
                ""));
  }

  @Test
  void csvFormulaAndUnicodeWhitespaceAreNeutralized() {
    for (String cell : List.of("=1+1", " +cmd", "\u00a0@SUM(A1)", "\ttext", "\rline"))
      assertTrue(Reports.csvSafe(cell).startsWith("'"));
    assertEquals("ordinary", Reports.csvSafe("ordinary"));
  }
}
