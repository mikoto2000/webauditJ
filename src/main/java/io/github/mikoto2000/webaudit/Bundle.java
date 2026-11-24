package io.github.mikoto2000.webaudit;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.util.*;

/** Batch-only investigation bundle. Original inputs and existing output paths are immutable. */
public final class Bundle {
  private Bundle() {}

  static MessageDigest sha() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  static String id(String prefix, String value) {
    return prefix
        + HexFormat.of()
            .formatHex(sha().digest(value.getBytes(StandardCharsets.UTF_8)))
            .substring(0, 32);
  }

  static String hash(Path path, long limit) throws IOException {
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
      throw new IOException("Not a regular input file");
    if (Files.size(path) > limit) return null;
    var hash = sha();
    try (var in = Files.newInputStream(path)) {
      byte[] data = new byte[65536];
      long total = 0;
      int n;
      while ((n =
              in.read(
                  data, 0, (int) (limit - total >= data.length ? data.length : limit - total + 1)))
          != -1) {
        total += n;
        if (total > limit) return null;
        hash.update(data, 0, n);
      }
    }
    return HexFormat.of().formatHex(hash.digest());
  }

  static OutputStream privateOutput(Path path) throws IOException {
    if (path.getFileSystem().supportedFileAttributeViews().contains("posix"))
      return java.nio.channels.Channels.newOutputStream(
          Files.newByteChannel(
              path,
              Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
              PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))));
    return Files.newOutputStream(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
  }

  static String rulesHash() throws IOException {
    var hash = sha();
    for (Object object : (List<?>) Json.resource("report-resources.json")) {
      String name = (String) object;
      hash.update((name + "\0").getBytes(StandardCharsets.UTF_8));
      try (var in = Bundle.class.getResourceAsStream("/" + name)) {
        if (in == null) throw new IOException("Missing bundled rules resource");
        hash.update(in.readAllBytes());
      }
    }
    return HexFormat.of().formatHex(hash.digest());
  }

  static Map<String, Object> settings(Options o, BundleOptions b) {
    return Json.map(
        "parser",
        o.logRegex.isEmpty() ? "auto" : "custom-regex",
        "custom_regex",
        "[not recorded]",
        "custom_regex_sha256",
        o.logRegex.isEmpty()
            ? null
            : HexFormat.of().formatHex(sha().digest(o.logRegex.getBytes(StandardCharsets.UTF_8))),
        "error_timezone",
        o.errorTimezone,
        "dedup_files",
        o.deduplicateFiles,
        "max_line_bytes",
        o.maxLineBytes,
        "max_file_bytes",
        o.maxFileBytes,
        "max_keys",
        o.maxKeys,
        "max_findings",
        o.maxFindings,
        "max_evidence_bytes",
        o.maxEvidenceBytes,
        "max_spool_bytes",
        b.maxSpoolBytes,
        "max_output_bytes",
        b.maxOutputBytes,
        "language",
        b.language,
        "recorded_peer",
        "forwarded headers are not trusted");
  }

  public static Map<String, Object> generate(
      List<Path> paths, Path target, Options o, BundleOptions b) throws IOException {
    Objects.requireNonNull(o);
    Objects.requireNonNull(b);
    if (!Set.of("ja", "en").contains(b.language)) throw new IOException("--lang must be ja or en");
    if (o.maxKeys < 1
        || o.maxFindings < 1
        || o.maxLineBytes < 1
        || o.maxFileBytes < 1
        || o.maxEvidenceBytes < 1
        || b.maxOutputBytes < 1
        || b.maxSpoolBytes < 1) throw new IOException("Invalid bundle resource limits");
    if (paths.size() > o.maxKeys)
      throw new IOException("Explicit input path limit exceeded (max-keys)");
    if (!o.logRegex.isEmpty())
      try {
        var p = com.google.re2j.Pattern.compile(o.logRegex);
        for (String name : List.of("ip", "time", "target"))
          if (!p.namedGroups().containsKey(name))
            throw new IOException("Custom regex requires named group " + name);
      } catch (IllegalArgumentException ex) {
        throw new IOException("Invalid custom regex; pattern not recorded");
      }
    target = target.toAbsolutePath().normalize();
    if (target.getFileSystem().supportedFileAttributeViews().contains("posix"))
      Files.createDirectory(
          target,
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    else Files.createDirectory(target);
    Path marker = target.resolve("INCOMPLETE");
    try (var out = privateOutput(marker)) {
      out.write(
          "Report generation is incomplete. Do not treat these artifacts as completed.\n"
              .getBytes(StandardCharsets.UTF_8));
    }
    var writer = new BundleWriter(target, b.maxOutputBytes);
    var capture = new BundleCapture(o);
    var previous = o.bundle;
    boolean retained = o.retainUpstreamEvidence;
    String started = Times.instant(o.clock.instant());
    Map<String, Object> analysis;
    try {
      o.bundle = capture;
      o.retainUpstreamEvidence = true;
      analysis = Engine.analyze(paths, o);
    } finally {
      o.bundle = previous;
      o.retainUpstreamEvidence = retained;
    }
    for (String warning : b.warnings) Engine.warn(analysis, warning);
    boolean complete = !Json.bool(analysis.get("partial"));
    var inventory = new ArrayList<Map<String, Object>>();
    for (var in : Json.rows(analysis.get("files"))) {
      String path = Json.string(in.get("path"));
      var row = capture.inputs.get(path);
      if (row == null) {
        row = capture.begin(Path.of(path));
        row.put("status", "failed");
        row.put("count_quality", "unavailable");
        row.put("error", in.get("error"));
      }
      if (Set.of("partial", "failed").contains(row.get("status"))) complete = false;
      inventory.add(row);
    }
    if (capture.diagnosticsTruncated) {
      complete = false;
      Engine.warn(analysis, "Report diagnostic limit reached; diagnostic samples are incomplete");
    }
    if (!complete) {
      analysis.put("partial", true);
      Engine.warn(
          analysis,
          "Investigation report is incomplete; inspect inventory and diagnostic completeness");
    }
    String status =
        complete ? "completed" : Json.number(analysis.get("requests")) == 0 ? "failed" : "partial";
    var report =
        Json.map(
            "schema",
            "webaudit/investigation-1",
            "metadata",
            b.map(),
            "started_at",
            started,
            "finished_at",
            Times.instant(o.clock.instant()),
            "settings",
            settings(o, b),
            "inventory",
            inventory,
            "analysis",
            analysis,
            "complete",
            complete,
            "status",
            status,
            "count_quality",
            complete ? "exact" : "lower_bound");
    writer.csv(
        "log-inventory.csv",
        List.of(
            "file_id",
            "path",
            "size_bytes",
            "sha256",
            "hash_scope",
            "compression",
            "first",
            "last",
            "total_lines",
            "parsed",
            "unparsed",
            "excluded",
            "status",
            "truncated",
            "changed",
            "error",
            "formats",
            "log_types",
            "timezones",
            "timezones_truncated",
            "available_fields"),
        write -> {
          for (var row : inventory)
            write.accept(
                cell(row, "id"),
                cell(row, "path"),
                cell(row, "size_bytes"),
                cell(row, "sha256"),
                cell(row, "hash_scope"),
                cell(row, "compression"),
                cell(row, "first"),
                cell(row, "last"),
                cell(row, "total_lines"),
                cell(row, "parsed"),
                cell(row, "unparsed"),
                cell(row, "excluded"),
                cell(row, "status"),
                cell(row, "truncated"),
                cell(row, "changed_during_analysis"),
                cell(row, "error"),
                join(row.get("formats")),
                join(row.get("log_types")),
                join(row.get("timezones")),
                cell(row, "timezones_truncated"),
                join(row.get("available_fields")));
        });
    for (String name : List.of("parse-errors", "excluded-requests")) {
      var rows = name.equals("parse-errors") ? capture.diagnostics : capture.excluded;
      writer.csv(
          "diagnostics/" + name + ".csv",
          List.of("file_id", "source_file", "source_line", "reason", "sample_complete"),
          write -> {
            for (var row : rows)
              write.accept(
                  cell(row, "file_id"),
                  cell(row, "source_file"),
                  cell(row, "source_line"),
                  cell(row, "reason"),
                  Boolean.toString(!capture.diagnosticsTruncated));
          });
    }
    var log =
        new StringBuilder(
            "WebAuditJ "
                + Engine.VERSION
                + "\nStarted: "
                + started
                + "\nFinished: "
                + report.get("finished_at")
                + "\nStatus: "
                + status
                + "\n");
    for (Object warning : (List<?>) analysis.get("warnings"))
      log.append(Reports.terminal(warning.toString())).append('\n');
    writer.text("diagnostics/execution-log.txt", log.toString());
    writer.json("report.json", report);
    writer.write(
        "report.html",
        out -> {
          var html = new OutputStreamWriter(out, StandardCharsets.UTF_8);
          Reports.write(html, analysis, "html", b.language);
          html.flush();
        });
    var manifest =
        Json.map(
            "schema",
            "webaudit/manifest-1",
            "version",
            Engine.VERSION,
            "build",
            Json.map(
                "java_version",
                System.getProperty("java.version"),
                "os",
                System.getProperty("os.name"),
                "arch",
                System.getProperty("os.arch")),
            "started_at",
            started,
            "finished_at",
            report.get("finished_at"),
            "settings",
            report.get("settings"),
            "rules_version",
            Engine.RULES_VERSION,
            "rules_sha256",
            rulesHash(),
            "geoip",
            analysis.get("geoip"),
            "inputs",
            inventory,
            "complete",
            report.get("complete"),
            "warnings",
            analysis.get("warnings"),
            "artifacts",
            writer.artifacts(),
            "artifact_hash_scope",
            "all listed artifacts; manifest excludes its own hash");
    writer.json("manifest.json", manifest);
    Files.delete(marker);
    return report;
  }

  static String cell(Map<String, Object> row, String key) {
    return Json.string(row.get(key));
  }

  static String join(Object rows) {
    return rows instanceof Collection<?> c
        ? String.join(";", c.stream().map(Object::toString).toList())
        : "";
  }
}
