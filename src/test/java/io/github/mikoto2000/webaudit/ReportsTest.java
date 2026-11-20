package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class ReportsTest {
  @TempDir Path dir;

  Map<String, Object> report() throws Exception {
    Path p = dir.resolve("a.log");
    Files.writeString(
        p, CorrelatorTest.event(0, 404).raw.replace("/.env", "/.env?q=<script>alert(1)</script>"));
    return Engine.analyze(List.of(p), new Options());
  }

  @Test
  void emitsAllFormatsAndEscapesUntrustedValues() throws Exception {
    var r = report();
    for (String format : List.of("json", "csv", "html", "summary")) {
      var out = new StringWriter();
      Reports.write(out, r, format);
      String text = out.toString();
      assertFalse(text.isEmpty(), format);
      if (format.equals("json")) UpstreamTest.equalJson(r, Json.object(text));
      if (format.equals("html")) {
        assertFalse(text.contains("<script>"));
        assertTrue(text.contains("&lt;script&gt;"));
        assertFalse(text.contains("<script src="));
      }
      if (format.equals("csv")) {
        assertTrue(
            text.startsWith(
                "record_type,id,severity,verdict,ip,observations,reasons,evidence_json,details_json"));
        assertTrue(text.contains("metadata,"));
      }
    }
  }

  @Test
  void propagatesWriteFailuresAndNeutralizesTerminalAndCsvControls() throws Exception {
    var r = report();
    r.put("warnings", List.of("bad\u001b[31m\u202e"));
    var out = new StringWriter();
    Reports.write(out, r, "summary");
    assertFalse(out.toString().contains("\u001b"));
    assertFalse(out.toString().contains("\u202e"));
    Writer broken =
        new Writer() {
          public void write(char[] c, int a, int b) throws IOException {
            throw new IOException("broken");
          }

          public void flush() {}

          public void close() {}
        };
    for (String format : List.of("json", "csv", "html", "summary"))
      assertThrows(IOException.class, () -> Reports.write(broken, r, format));
  }
}
