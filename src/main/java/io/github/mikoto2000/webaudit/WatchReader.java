package io.github.mikoto2000.webaudit;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;

final class WatchReader implements AutoCloseable {
  static final class InvalidInput extends IOException {
    InvalidInput(String message) {
      super(message);
    }
  }

  @FunctionalInterface
  interface Line {
    void accept(String text, String file, long number) throws IOException;
  }

  final List<String> targets;
  final WatchCommand.Arguments o;
  final Consumer<String> warn;
  final List<Cursor> files = new ArrayList<>();
  boolean initialized;
  boolean scanIncomplete;
  final PathMatcher include, exclude;

  static final class Cursor {
    Path path;
    String id, anchor = "";
    FileChannel channel;
    long offset, number;
    boolean known, discard;
    Instant detached;
    final ByteArrayOutputStream partial = new ByteArrayOutputStream();
  }

  WatchReader(WatchCommand.Arguments o, Consumer<String> warn) throws IOException {
    this.o = o;
    this.warn = warn;
    targets =
        o.inputs.stream()
            .map(p -> p.toAbsolutePath().normalize().toString())
            .distinct()
            .sorted()
            .toList();
    include =
        o.include.isEmpty() ? null : FileSystems.getDefault().getPathMatcher("glob:" + o.include);
    exclude =
        o.exclude.isEmpty() ? null : FileSystems.getDefault().getPathMatcher("glob:" + o.exclude);
    try {
      discover();
      initialized = true;
    } catch (IOException | RuntimeException ex) {
      close();
      throw ex;
    }
  }

  static void noLinks(Path path) throws IOException {
    for (Path p = path; p != null; p = p.getParent())
      if (Files.isSymbolicLink(p) && !macSystemAlias(p))
        throw new InvalidInput("symlink path rejected: " + path);
  }

  private static boolean macSystemAlias(Path path) throws IOException {
    if (!Main.os().equals("darwin")) return false;
    Path absolute = path.toAbsolutePath().normalize();
    if (!Set.of(Path.of("/var"), Path.of("/tmp"), Path.of("/etc")).contains(absolute)) return false;
    // macOS owns these root-level aliases. Do not relax checks for user-created links.
    Path target = absolute.getParent().resolve(Files.readSymbolicLink(absolute)).normalize();
    return target.equals(Path.of("/private").resolve(absolute.getFileName()));
  }

  static BasicFileAttributes attrs(Path p) throws IOException {
    noLinks(p);
    return Files.readAttributes(p, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
  }

  static String identity(Path p, BasicFileAttributes a) throws IOException {
    if (Main.os().equals("windows")) return WatchNative.fileID(p);
    if (a.fileKey() == null)
      throw new IOException("filesystem does not provide stable file identity: " + p);
    return a.fileKey().toString();
  }

  boolean selected(Path name) {
    String n = name.toString().toLowerCase(Locale.ROOT);
    boolean candidate =
        include != null
            ? include.matches(name)
            : n.equals("access")
                || n.equals("access.log")
                || n.endsWith("_access.log")
                || n.endsWith("-access.log")
                || n.endsWith(".access.log");
    return candidate && (exclude == null || !exclude.matches(name));
  }

  SortedSet<Path> candidates() throws IOException {
    var paths = new TreeSet<Path>();
    for (String s : targets) {
      Path p = Path.of(s);
      try {
        var a = attrs(p);
        if (a.isDirectory()) {
          try (var stream = Files.newDirectoryStream(p)) {
            for (var f : stream) if (selected(f.getFileName())) paths.add(f);
          }
        } else {
          if (p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".gz"))
            throw new InvalidInput("compressed watch input rejected: " + p);
          paths.add(p);
        }
      } catch (NoSuchFileException ignored) {
      } catch (InvalidInput ex) {
        throw ex;
      } catch (IOException ex) {
        scanIncomplete = true;
        warn.accept("input unavailable: " + p);
      }
    }
    return paths;
  }

  void discover() throws IOException {
    scanIncomplete = false;
    var paths = candidates();
    var active = new HashSet<String>();
    for (var p : paths) {
      try {
        var a = attrs(p);
        if (!a.isRegularFile()) throw new InvalidInput("watch input must be a regular file: " + p);
        String id = identity(p, a);
        active.add(id);
        Cursor same = files.stream().filter(c -> c.id.equals(id)).findFirst().orElse(null);
        if (same != null) {
          if (same.path.equals(p)) same.detached = null;
          continue;
        }
        if (files.size() >= o.maxFiles) {
          warn.accept("open file limit reached");
          continue;
        }
        Cursor c = new Cursor();
        c.path = p;
        c.id = id;
        c.channel = FileChannel.open(p, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
        try {
          // Verify identity after opening; do not restore an offset into a replacement file.
          if (!id.equals(identity(p, attrs(p))))
            throw new IOException("input changed while opening");
          ByteBuffer magic = ByteBuffer.allocate(2);
          c.channel.read(magic, 0);
          if (magic.position() == 2 && magic.get(0) == (byte) 0x1f && magic.get(1) == (byte) 0x8b)
            throw new InvalidInput("gzip input rejected in watch: " + p);
          c.known = initialized || o.from.equals("beginning");
          if (!c.known) {
            c.offset = c.channel.size();
            c.known = c.offset == 0;
            if (c.offset > 0) {
              ByteBuffer last = ByteBuffer.allocate(1);
              c.channel.read(last, c.offset - 1);
              c.discard = last.get(0) != '\n';
            }
          }
          c.anchor = anchor(c);
          files.add(c);
        } catch (IOException ex) {
          c.channel.close();
          throw ex;
        }
      } catch (NoSuchFileException ignored) {
      } catch (InvalidInput ex) {
        throw ex;
      } catch (IOException ex) {
        scanIncomplete = true;
        warn.accept("input unavailable: " + p);
      }
    }
    if (!scanIncomplete)
      for (var c : files)
        if (!active.contains(c.id) && c.detached == null) c.detached = Instant.now();
  }

  static String anchor(Cursor c) throws IOException {
    int n = (int) Math.min(c.offset, 128);
    ByteBuffer b = ByteBuffer.allocate(n);
    long start = c.offset - n;
    while (b.hasRemaining()) {
      int read = c.channel.read(b, start + b.position());
      if (read <= 0) break;
    }
    return HexFormat.of().formatHex(Core.sha(Arrays.copyOf(b.array(), b.position())));
  }

  void poll(Line sink) throws IOException {
    discover();
    for (var c : new ArrayList<>(files)) {
      if (Thread.currentThread().isInterrupted()) return;
      // A replacement waits until the detached predecessor's backlog has drained.
      if (c.detached == null
          && files.stream()
              .anyMatch(old ->
                  old != c && old.path.equals(c.path) && old.detached != null && unread(old)))
        continue;
      try {
        if (c.channel.size() < c.offset || !anchor(c).equals(c.anchor)) {
          warn.accept("copytruncate/rewrite detected: " + c.path);
          c.offset = 0;
          c.number = 0;
          c.known = true;
          c.discard = false;
          c.partial.reset();
        }
        long budget = 1 << 20;
        ByteBuffer b = ByteBuffer.allocate(8192);
        while (budget > 0 && !Thread.currentThread().isInterrupted()) {
          b.clear();
          b.limit((int) Math.min(b.capacity(), budget));
          int n = c.channel.read(b, c.offset);
          if (n <= 0) break;
          c.offset += n;
          budget -= n;
          for (int i = 0; i < n; i++) {
            byte v = b.get(i);
            if (v == '\n') {
              if (c.known) c.number++;
              if (!c.discard) {
                byte[] bytes = c.partial.toByteArray();
                int len = bytes.length;
                if (len > 0 && bytes[len - 1] == '\r') len--;
                try {
                  String text =
                      StandardCharsets.UTF_8
                          .newDecoder()
                          .onMalformedInput(CodingErrorAction.REPORT)
                          .onUnmappableCharacter(CodingErrorAction.REPORT)
                          .decode(ByteBuffer.wrap(bytes, 0, len))
                          .toString();
                  try {
                    sink.accept(text, c.path.toString(), c.known ? c.number : 0);
                  } catch (IOException ex) {
                    throw new UncheckedIOException(ex);
                  }
                } catch (CharacterCodingException ex) {
                  warn.accept("invalid UTF-8 log line skipped");
                }
              }
              c.partial.reset();
              c.discard = false;
            } else if (!c.discard) {
              if (c.partial.size() >= o.maxLine) {
                c.partial.reset();
                c.discard = true;
                warn.accept("line byte limit reached");
              } else c.partial.write(v);
            }
          }
        }
        c.anchor = anchor(c);
        if (c.detached != null && !unread(c) && Instant.now().isAfter(c.detached.plusSeconds(2))) {
          if (c.partial.size() > 0) warn.accept("incomplete rotated line discarded");
          c.channel.close();
          files.remove(c);
        }
      } catch (IOException ex) {
        warn.accept("input temporarily unavailable: " + c.path);
      }
    }
  }

  static boolean unread(Cursor c) {
    try {
      return c.channel.size() > c.offset;
    } catch (IOException ex) {
      return true;
    }
  }

  Map<String, Object> snapshot() {
    return Json.map(
        "cursors",
        files.stream()
            .map(c ->
                Json.map(
                    "path",
                    c.path.toString(),
                    "id",
                    c.id,
                    "offset",
                    c.offset,
                    "number",
                    c.number,
                    "known",
                    c.known,
                    "discard",
                    c.discard,
                    "partial",
                    Base64.getEncoder().encodeToString(c.partial.toByteArray()),
                    "anchor",
                    c.anchor))
            .toList());
  }

  void restore(Map<String, Object> state) throws IOException {
    var cursors = Json.rows(state.get("cursors"));
    if (cursors.size() > o.maxFiles) throw new IOException("too many saved cursors");
    var restored = new HashSet<String>();
    for (var m : cursors) {
      Path p = Path.of(Json.string(m.get("path")));
      if (!p.isAbsolute()
          || targets.stream()
              .noneMatch(t -> p.toString().equals(t) || Objects.equals(p.getParent(), Path.of(t))))
        throw new IOException("cursor outside targets");
      long offset = Json.number(m.get("offset")), number = Json.number(m.get("number"));
      byte[] partial = Base64.getDecoder().decode(Json.string(m.get("partial")));
      if (!(m.get("offset") instanceof Number)
          || !(m.get("number") instanceof Number)
          || Json.string(m.get("id")).isEmpty()
          || !Json.string(m.get("anchor")).matches("[0-9a-f]{64}")
          || offset < 0
          || number < 0
          || partial.length > o.maxLine
          || !restored.add(Json.string(m.get("id")))) throw new IOException("invalid cursor");
      var c = files.stream().filter(f -> f.id.equals(m.get("id"))).findFirst().orElse(null);
      if (c == null) c = findRotated(p, Json.string(m.get("id")));
      if (c == null) {
        warn.accept("saved file identity unavailable: " + p);
        continue;
      }
      c.offset = offset;
      if (c.channel.size() < offset || !anchor(c).equals(m.get("anchor"))) {
        warn.accept("saved anchor mismatch; restarting file: " + p);
        c.offset = 0;
        c.number = 0;
        c.known = true;
        c.discard = false;
        c.partial.reset();
      } else {
        c.number = number;
        c.known = Json.bool(m.get("known"));
        c.discard = Json.bool(m.get("discard"));
        c.partial.reset();
        c.partial.writeBytes(partial);
      }
      c.anchor = anchor(c);
    }
    // Files created during downtime always start at the beginning.
    for (var c : files)
      if (!restored.contains(c.id)) {
        c.offset = 0;
        c.number = 0;
        c.known = true;
        c.discard = false;
        c.partial.reset();
        c.anchor = anchor(c);
      }
  }

  private Cursor findRotated(Path original, String id) throws IOException {
    if (files.size() >= o.maxFiles) {
      // Defer newly discovered replacements until the saved predecessor is drained.
      Cursor replacement =
          files.stream().filter(c -> c.path.equals(original)).findFirst().orElse(null);
      if (replacement == null) {
        warn.accept("restored handle limit reached");
        return null;
      }
      replacement.channel.close();
      files.remove(replacement);
    }
    try (var entries = Files.newDirectoryStream(original.getParent())) {
      int count = 0;
      for (var path : entries) {
        if (++count > 4096) break;
        try {
          var attributes = attrs(path);
          if (!attributes.isRegularFile() || !identity(path, attributes).equals(id)) continue;
          var channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
          try {
            if (!identity(path, attrs(path)).equals(id)) continue;
            var magic = ByteBuffer.allocate(2);
            channel.read(magic, 0);
            if (magic.position() == 2 && magic.get(0) == (byte) 0x1f && magic.get(1) == (byte) 0x8b)
              continue;
            Cursor c = new Cursor();
            c.path = original;
            c.id = id;
            c.channel = channel;
            c.detached = Instant.now();
            files.add(c);
            channel = null;
            return c;
          } finally {
            if (channel != null) channel.close();
          }
        } catch (IOException ignored) {
        }
      }
    } catch (IOException ex) {
      warn.accept("rotated file search unavailable: " + original.getParent());
    }
    return null;
  }

  public void close() throws IOException {
    IOException error = null;
    for (var c : files)
      try {
        c.channel.close();
      } catch (IOException ex) {
        error = ex;
      }
    files.clear();
    if (error != null) throw error;
  }
}
