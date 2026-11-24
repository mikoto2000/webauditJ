package io.github.mikoto2000.webaudit;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Map;

/** Private bounded snapshots; scanning never rereads the original evidence files. */
final class RequestSpool implements AutoCloseable {
  final Path path;
  final long limit;
  long used;
  boolean truncated;
  private OutputStream out;
  private IOException failure;

  RequestSpool(Path dir, long limit) throws IOException {
    path = Files.createTempFile(dir, ".requests-", "");
    this.limit = limit;
    try {
      out = new BufferedOutputStream(Files.newOutputStream(path, StandardOpenOption.WRITE), 65536);
    } catch (IOException e) {
      try {
        Files.delete(path);
      } catch (IOException cleanup) {
        e.addSuppressed(cleanup);
      }
      throw e;
    }
  }

  void write(Map<String, Object> snapshot) {
    if (truncated || failure != null) return;
    try {
      byte[] data = Json.MAPPER.writeValueAsBytes(snapshot);
      if (data.length + 1L > limit - used) {
        truncated = true;
        return;
      }
      out.write(data);
      out.write('\n');
      used += data.length + 1L;
    } catch (IOException e) {
      failure = e;
    } catch (RuntimeException e) {
      failure = new IOException("Request snapshot serialization failed", e);
    }
  }

  void finishWrite() throws IOException {
    if (out != null) {
      try {
        out.close();
      } catch (IOException e) {
        if (failure == null) failure = e;
        else failure.addSuppressed(e);
      } finally {
        out = null;
      }
    }
    if (failure != null) throw failure;
  }

  @FunctionalInterface
  interface Consume {
    void accept(Map<String, Object> snapshot) throws IOException;
  }

  void scan(Consume consume) throws IOException {
    finishWrite();
    try (var reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      String line;
      while ((line = reader.readLine()) != null) {
        try {
          consume.accept(Json.object(line));
        } catch (RuntimeException e) {
          throw new IOException("Request snapshot decoding failed", e);
        }
      }
    }
  }

  @Override
  public void close() throws IOException {
    IOException problem = null;
    try {
      finishWrite();
    } catch (IOException e) {
      problem = e;
    }
    try {
      Files.deleteIfExists(path);
    } catch (IOException e) {
      if (problem == null) problem = e;
      else problem.addSuppressed(e);
    }
    if (problem != null) throw problem;
  }
}
