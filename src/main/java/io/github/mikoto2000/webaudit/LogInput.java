package io.github.mikoto2000.webaudit;

import static io.github.mikoto2000.webaudit.Core.*;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;

final class LogInput {
  private final Options o;
  private final Map<String, Object> report;
  private final List<Map<String, Object>> inputs;
  private long parsed, unparsed, duplicates;
  private long progressLines;
  private int completedFiles;
  private final Map<String, Long> missing = new TreeMap<>();
  private OffsetDateTime first, last;
  private final Consumer<Event> consumer;
  private final TreeSet<Path> files = new TreeSet<>(Comparator.comparing(Path::toString));
  private static final com.google.re2j.Pattern LOG_NAME =
      com.google.re2j.Pattern.compile(
          "(?i)(\\.log(?:\\.[0-9]+)?(?:\\.gz)?$|\\.gz$|^access(?:\\.[0-9]+)?$)");

  LogInput(Options o, Map<String, Object> report, Consumer<Event> consumer) {
    this.o = o;
    this.report = report;
    this.consumer = consumer;
    inputs = new ArrayList<>();
    report.put("files", inputs);
  }

  void warn(String s) {
    Engine.warn(report, s);
  }

  private void partial() {
    report.put("partial", true);
  }

  private void walk(Path dir) {
    try (var stream = Files.list(dir)) {
      for (Path p : stream.sorted(Comparator.comparing(Path::toString)).toList()) {
        if (Files.isSymbolicLink(p)) continue;
        if (Files.isDirectory(p)) walk(p);
        else if (Files.isRegularFile(p) && LOG_NAME.matcher(p.getFileName().toString()).find()) {
          if (files.size() < o.maxKeys) files.add(p);
          else {
            warn("Input-file limit reached; directory coverage incomplete");
            partial();
          }
        }
      }
    } catch (IOException ex) {
      warn("directory " + dir + ": " + ex.getMessage());
      partial();
    }
  }

  void stream(List<Path> paths) {
    ZoneId errorZone = null;
    if (!o.errorTimezone.isEmpty()) {
      try {
        errorZone = TimeZones.resolve(o.errorTimezone);
        report.put("error_timezone", o.errorTimezone);
      } catch (DateTimeException e) {
        partial();
        warn("Invalid error log timezone: " + e.getMessage());
        finish();
        return;
      }
    }
    for (Path raw : paths) {
      Path p = raw.toAbsolutePath().normalize();
      if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS)) {
        inputs.add(
            Json.map(
                "path", p.toString(), "parsed", 0L, "unparsed", 0L, "error", "File not found"));
        partial();
        continue;
      }
      if (Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) walk(p);
      else if (Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) files.add(p);
      else {
        warn("Skipped non-regular input: " + p);
        partial();
      }
    }
    if (files.isEmpty()) {
      warn("No regular log files found");
      partial();
    }
    notifyProgress();
    var seen = new HashMap<String, Map<String, Object>>();
    for (Path p : files) {
      var in = Json.map("path", p.toString(), "parsed", 0L, "unparsed", 0L);
      if (o.bundle != null) o.bundle.begin(p);
      String signature = null;
      if (o.deduplicateFiles) {
        try {
          signature = hash(p);
          if (signature != null && seen.containsKey(signature)) {
            var old = seen.get(signature);
            in.put("parsed", old.get("parsed"));
            in.put("unparsed", old.get("unparsed"));
            in.put("duplicate_of", old.get("path"));
            parsed += Json.number(old.get("parsed"));
            unparsed += Json.number(old.get("unparsed"));
            duplicates += Json.number(old.get("parsed"));
            inputs.add(in);
            if (o.bundle != null) o.bundle.duplicate(p, Json.string(old.get("path")));
            completedFiles++;
            notifyProgress();
            continue;
          }
        } catch (IOException ignored) {
        }
      }
      ZoneId zone = errorZone;
      try {
        read(
            p,
            (bytes, line, tooLong) -> {
              progressLines++;
              notifyProgress();
              if (o.bundle != null) o.bundle.line(p);
              if (tooLong) {
                in.put("unparsed", Json.number(in.get("unparsed")) + 1);
                warn("Oversized line skipped (max-line-bytes)");
                if (o.bundle != null) o.bundle.bad(p, line, "oversized line (max-line-bytes)");
                return;
              }
              String text;
              try {
                text =
                    StandardCharsets.UTF_8
                        .newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(bytes))
                        .toString();
              } catch (CharacterCodingException ex) {
                bad(in, p, line, "invalid UTF-8 or control line");
                return;
              }
              if (text.codePoints().allMatch(Core::space)) {
                if (o.bundle != null) o.bundle.blank(p, line);
                return;
              }
              Event e;
              try {
                e = LogParser.parse(text, p.toString(), line, o.logRegex);
              } catch (IllegalArgumentException ex) {
                bad(in, p, line, ex.getMessage());
                return;
              }
              in.put("parsed", Json.number(in.get("parsed")) + 1);
              if (e.timezoneUnknown && zone != null) {
                e.time = e.time.toLocalDateTime().atZone(zone).toOffsetDateTime();
                e.timezoneUnknown = false;
              }
              if (!e.timezoneUnknown && (first == null || e.time.isBefore(first))) first = e.time;
              if (!e.timezoneUnknown && (last == null || e.time.isAfter(last))) last = e.time;
              Map<String, Boolean> absent =
                  Map.of(
                      "status",
                      e.status == null,
                      "bytes",
                      e.bytes == null,
                      "user_agent",
                      e.ua == null,
                      "referer",
                      e.referer == null,
                      "method",
                      e.method == null,
                      "protocol",
                      e.protocol == null,
                      "target",
                      e.target.isEmpty(),
                      "timezone",
                      e.timezoneUnknown);
              absent.forEach((key, value) -> {
                if (value) missing.merge(key, 1L, Long::sum);
              });
              if (o.bundle != null) o.bundle.event(e);
              consumer.accept(e);
            });
      } catch (IOException ex) {
        in.put("error", ex.getMessage());
        warn(p + ": " + ex.getMessage());
        partial();
      }
      if (o.bundle != null) o.bundle.finish(p, Json.string(in.get("error")));
      parsed += Json.number(in.get("parsed"));
      unparsed += Json.number(in.get("unparsed"));
      inputs.add(in);
      if (signature != null && !in.containsKey("error")) seen.put(signature, in);
      completedFiles++;
      notifyProgress();
    }
    if (duplicates > 0)
      warn(
          "Identical complete input files excluded by explicit --dedup-files; repeated requests"
              + " within a file are preserved");
    if (unparsed > 0) {
      partial();
      warn(
          "Unparsed lines reduce detection coverage; inspect file/line diagnostics and"
              + " --log-regex");
    }
    warn(
        "Request bodies and response contents are unavailable; authentication results and"
            + " compromise cannot be verified");
    warn(
        "Client address is the recorded peer; forwarded headers are untrusted and proxy topology is"
            + " unknown");
    finish();
  }

  private void notifyProgress() {
    if (o.progress != null)
      o.progress.accept(new InputProgress(completedFiles, files.size(), progressLines));
  }

  private void finish() {
    report.put("requests", parsed);
    report.put("unparsed", unparsed);
    report.put("duplicates", duplicates);
    report.put("first", Times.text(first));
    report.put("last", Times.text(last));
    report.put("missing_fields", missing);
  }

  private void bad(Map<String, Object> in, Path path, long line, String reason) {
    if (o.bundle != null) o.bundle.bad(path, line, reason);
    long n = Json.number(in.get("unparsed")) + 1;
    in.put("unparsed", n);
    if (n <= 3) warn(path + ":" + line + ": " + reason);
  }

  private String hash(Path p) throws IOException {
    try {
      var h = MessageDigest.getInstance("SHA-256");
      long n = 0;
      try (var in = Files.newInputStream(p)) {
        byte[] b = new byte[65536];
        int count;
        while ((count = in.read(b)) != -1) {
          n += count;
          if (n > o.maxFileBytes) return null;
          h.update(b, 0, count);
        }
      }
      return HexFormat.of().formatHex(h.digest());
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  @FunctionalInterface
  private interface Line {
    void accept(byte[] bytes, long line, boolean tooLong);
  }

  private void read(Path p, Line line) throws IOException {
    try (var raw = new BufferedInputStream(Files.newInputStream(p), 65536)) {
      raw.mark(2);
      int a = raw.read(), b = raw.read();
      raw.reset();
      InputStream body = a == 0x1f && b == 0x8b ? new StrictGzipInputStream(raw) : raw;
      try (var input = body) {
        byte[] buffer = new byte[65536];
        var data = new ByteArrayOutputStream();
        long total = 0, lineNumber = 0;
        boolean tooLong = false;
        int count;
        while ((count =
                input.read(buffer, 0, (int) Math.min(buffer.length, o.maxFileBytes - total + 1)))
            != -1) {
          for (int i = 0; i < count; i++) {
            total++;
            if (total > o.maxFileBytes)
              throw new IOException("decompressed file limit reached; analysis incomplete");
            int c = buffer[i] & 255;
            if (!tooLong) {
              if (data.size() + 1 <= o.maxLineBytes + 1) data.write(c);
              else {
                tooLong = true;
                data.reset();
              }
            }
            if (c == '\n') {
              byte[] bytes = data.toByteArray();
              int n = bytes.length;
              if (n > 0 && bytes[n - 1] == '\n') n--;
              if (n > 0 && bytes[n - 1] == '\r') n--;
              line.accept(Arrays.copyOf(bytes, n), ++lineNumber, tooLong || n > o.maxLineBytes);
              data.reset();
              tooLong = false;
            }
          }
        }
        if (data.size() > 0 || tooLong) {
          byte[] bytes = data.toByteArray();
          int n = bytes.length;
          if (n > 0 && bytes[n - 1] == '\r') n--;
          line.accept(Arrays.copyOf(bytes, n), ++lineNumber, tooLong || n > o.maxLineBytes);
        }
      }
    }
  }
}
