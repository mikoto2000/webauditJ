package io.github.mikoto2000.webaudit;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.apache.commons.csv.*;

/** Exclusive artifact creation with one shared byte budget, including manifest. */
final class BundleWriter {
  final Path dir;
  final long limit;
  long used;
  boolean maskSecrets = true;
  final List<String> files = new ArrayList<>();

  BundleWriter(Path dir, long limit) {
    this.dir = dir;
    this.limit = limit;
  }

  @FunctionalInterface
  interface Write {
    void accept(OutputStream out) throws IOException;
  }

  @FunctionalInterface
  interface Record {
    void accept(String... cells) throws IOException;
  }

  @FunctionalInterface
  interface Rows {
    void accept(Record record) throws IOException;
  }

  void write(String name, Write fn) throws IOException {
    Path relative = Path.of(name);
    if (relative.isAbsolute() || relative.normalize().startsWith(".."))
      throw new IOException("Invalid artifact path");
    Path path = dir.resolve(relative);
    Files.createDirectories(path.getParent());
    try (var target = Bundle.privateOutput(path);
        var out =
            new OutputStream() {
              @Override
              public void write(int b) throws IOException {
                write(new byte[] {(byte) b}, 0, 1);
              }

              @Override
              public void write(byte[] b, int offset, int size) throws IOException {
                if (size > limit - used) throw new IOException("Report output byte limit reached");
                target.write(b, offset, size);
                used += size;
              }

              @Override
              public void flush() throws IOException {
                target.flush();
              }
            }) {
      files.add(name.replace('\\', '/'));
      fn.accept(out);
    }
  }

  void text(String name, String text) throws IOException {
    write(name, out -> out.write(text.getBytes(StandardCharsets.UTF_8)));
  }

  void json(String name, Object value) throws IOException {
    write(
        name,
        out -> {
          try {
            out.write(Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(value));
            out.write('\n');
          } catch (RuntimeException ex) {
            throw new IOException("JSON report failed", ex);
          }
        });
  }

  void csv(String name, List<String> header, Rows rows) throws IOException {
    write(
        name,
        out -> {
          try (var writer =
                  new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
              var csv =
                  new CSVPrinter(
                      writer, CSVFormat.DEFAULT.builder().setRecordSeparator("\n").get())) {
            csv.printRecord(header);
            rows.accept(cells -> {
              var safe = new ArrayList<String>();
              for (int i = 0; i < cells.length; i++)
                safe.add(
                    Reports.csvSafe(
                        BundleMask.csv(
                            cells[i], i < header.size() ? header.get(i) : "", maskSecrets)));
              csv.printRecord(safe);
            });
          }
        });
  }

  List<Map<String, Object>> artifacts() throws IOException {
    var result = new ArrayList<Map<String, Object>>();
    for (String name : files) {
      Path path = dir.resolve(name);
      result.add(
          Json.map("path", name, "sha256", Bundle.hash(path, limit), "bytes", Files.size(path)));
    }
    return result;
  }
}
