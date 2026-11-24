package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BundleTest {
  @TempDir Path dir;
  static final String LINE =
      "192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] \"GET /.env HTTP/1.1\" 404 0 \"-\" \"Browser\"";

  static String hash(byte[] data) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
  }

  @Test
  void hashesLargeLimitsAndDisclosesGrowthBeyondHashCap() throws Exception {
    Path input = dir.resolve("growing.log");
    Files.writeString(input, "a\n");
    assertEquals(hash(Files.readAllBytes(input)), Bundle.hash(input, Long.MAX_VALUE));
    var o = new Options();
    o.maxFileBytes = 5;
    var capture = new BundleCapture(o);
    capture.begin(input);
    Files.writeString(input, "abcdefghi\n");
    capture.finish(input, "decompressed file limit reached");
    assertEquals(
        true,
        capture
            .inputs
            .get(input.toAbsolutePath().normalize().toString())
            .get("changed_during_analysis"));
  }

  @Test
  void disclosesDedupEmptyUnreadableAndPrivateSettings() throws Exception {
    Path a = dir.resolve("a.log"), b = dir.resolve("b.log"), empty = dir.resolve("empty.log");
    Files.writeString(a, LINE + "\n");
    Files.copy(a, b);
    Files.writeString(empty, "");
    var options = new Options();
    options.deduplicateFiles = true;
    var report =
        Bundle.generate(
            List.of(a, b, empty, dir.resolve("missing.log")),
            dir.resolve("report"),
            options,
            new BundleOptions());
    assertFalse(Json.bool(report.get("complete")));
    assertEquals(4, Json.rows(report.get("inventory")).size());
    assertTrue(
        Json.rows(report.get("inventory")).stream()
            .anyMatch(row ->
                "excluded_duplicate".equals(row.get("status"))
                    && Json.number(row.get("excluded")) == 1));
    assertTrue(
        Json.rows(report.get("inventory")).stream()
            .anyMatch(row -> "failed".equals(row.get("status"))));
    var privateOptions = new Options();
    privateOptions.logRegex = "(?P<ip>\\S+) (?P<time>SECRET) (?P<target>\\S+)";
    var settings = Bundle.settings(privateOptions, new BundleOptions());
    assertFalse(Json.MAPPER.writeValueAsString(settings).contains("SECRET"));
    assertNotNull(settings.get("custom_regex_sha256"));
  }

  @Test
  void inventoriesOriginalGzipAndSealsEveryArtifact() throws Exception {
    Path input = dir.resolve("input.log.gz");
    try (var z = new GZIPOutputStream(Files.newOutputStream(input))) {
      z.write((LINE + "\n\nbad record\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
    var options = new BundleOptions();
    options.system = "<system>";
    options.investigator = "tester";
    Path target = dir.resolve("report");
    var report = Bundle.generate(List.of(input), target, new Options(), options);
    assertEquals("webaudit/investigation-1", report.get("schema"));
    assertEquals("partial", report.get("status"));
    var inventory = Json.rows(report.get("inventory"));
    assertEquals(1, inventory.size());
    var file = inventory.getFirst();
    assertEquals(hash(Files.readAllBytes(input)), file.get("sha256"));
    assertEquals("original_file_bytes", file.get("hash_scope"));
    assertEquals("gzip", file.get("compression"));
    assertEquals(3, Json.number(file.get("total_lines")));
    assertEquals(1, Json.number(file.get("parsed")));
    assertEquals(1, Json.number(file.get("unparsed")));
    assertEquals(1, Json.number(file.get("excluded")));
    var manifest = Json.object(Files.readString(target.resolve("manifest.json")));
    assertEquals("webaudit/manifest-1", manifest.get("schema"));
    assertFalse(Json.string(manifest.get("rules_sha256")).isEmpty());
    for (var artifact : Json.rows(manifest.get("artifacts"))) {
      byte[] data = Files.readAllBytes(target.resolve((String) artifact.get("path")));
      assertEquals(hash(data), artifact.get("sha256"));
      assertEquals(data.length, Json.number(artifact.get("bytes")));
    }
    assertFalse(Files.exists(target.resolve("INCOMPLETE")));
    assertThrows(
        IOException.class, () -> Bundle.generate(List.of(input), target, new Options(), options));
  }

  @Test
  void marksChangedInputsAndFailedOutputWithoutChangingOriginal() throws Exception {
    Path input = dir.resolve("access.log");
    Files.writeString(input, "before\n");
    var capture = new BundleCapture(new Options());
    capture.begin(input);
    Files.writeString(input, "after\n");
    capture.finish(input, null);
    assertEquals(
        true,
        capture
            .inputs
            .get(input.toAbsolutePath().normalize().toString())
            .get("changed_during_analysis"));
    Path target = dir.resolve("limited");
    var limits = new BundleOptions();
    limits.maxOutputBytes = 1;
    assertThrows(
        IOException.class, () -> Bundle.generate(List.of(input), target, new Options(), limits));
    assertTrue(Files.exists(target.resolve("INCOMPLETE")));
    assertEquals("after\n", Files.readString(input));
  }

  @Test
  void exposesBundleCLIAndRejectsConflictingOutputBeforeCreation() throws Exception {
    Path input = dir.resolve("access.log");
    Files.writeString(input, LINE + "\n");
    Path target = dir.resolve("bundle");
    var out = new StringWriter();
    var err = new StringWriter();
    assertEquals(
        0,
        Main.run(
            new String[] {
              input.toString(),
              "--report-dir",
              target.toString(),
              "--system-name",
              "sample",
              "--lang",
              "en"
            },
            out,
            err,
            Map.of(),
            null,
            null),
        err.toString());
    assertEquals(
        "sample",
        Json.obj(Json.object(Files.readString(target.resolve("report.json"))).get("metadata"))
            .get("system"));
    Path conflict = dir.resolve("conflict");
    assertEquals(
        2,
        Main.run(
            new String[] {
              input.toString(), "--report-dir", conflict.toString(), "--format", "json"
            },
            new StringWriter(),
            new StringWriter(),
            Map.of(),
            null,
            null));
    assertFalse(Files.exists(conflict));
  }
}
