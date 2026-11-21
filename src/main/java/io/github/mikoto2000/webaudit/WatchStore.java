package io.github.mikoto2000.webaudit;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;

/** Private, checksummed, atomically replaced snapshots with a session OS lock. */
final class WatchStore implements AutoCloseable {
  static final int MAX_BYTES = 32 << 20;
  final Path path;
  final String key;
  final List<String> targets;
  final boolean reset;
  FileChannel channel;
  FileLock lock;

  WatchStore(Path dir, List<String> targets, String key, boolean reset) throws IOException {
    this.key = key;
    this.targets = targets.stream().distinct().sorted().toList();
    this.reset = reset;
    dir = dir.toAbsolutePath().normalize();
    WatchReader.noLinks(dir);
    ManagedFiles.directories(dir);
    String name = WatchEngine.hash(String.join("\0", this.targets));
    path = dir.resolve(name + ".json");
    regular(path);
    Path lp = dir.resolve(name + ".lock");
    regular(lp);
    if (!Files.exists(lp, LinkOption.NOFOLLOW_LINKS))
      try {
        ManagedFiles.createFile(lp);
      } catch (FileAlreadyExistsException ignored) {
      }
    channel = FileChannel.open(lp, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
    try {
      lock = channel.tryLock();
      if (lock == null) throw new IOException("watch session already locked");
    } catch (IOException | RuntimeException ex) {
      channel.close();
      throw new IOException("watch session already locked", ex);
    }
    try (var files = Files.newDirectoryStream(dir, ".state-*.tmp")) {
      int n = 0;
      for (var f : files) {
        if (n++ >= 128) break;
        if (Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS)
            && Files.getLastModifiedTime(f, LinkOption.NOFOLLOW_LINKS)
                .toInstant()
                .isBefore(Instant.now().minusSeconds(86400))) Files.delete(f);
      }
    } catch (IOException ignored) {
    }
  }

  static void regular(Path p) throws IOException {
    WatchReader.noLinks(p);
    if (Files.exists(p, LinkOption.NOFOLLOW_LINKS)
        && !Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS))
      throw new IOException("state path must be regular");
  }

  static Path directory(Map<String, String> env) {
    String root = env.getOrDefault("XDG_STATE_HOME", "");
    if (root.isEmpty())
      root =
          Main.os().equals("windows")
              ? env.getOrDefault("LOCALAPPDATA", "")
              : Path.of(
                      env.getOrDefault("HOME", System.getProperty("user.home")), ".local", "state")
                  .toString();
    if (root.isEmpty() || !Path.of(root).isAbsolute())
      throw new IllegalArgumentException("watch state root must be absolute");
    return Path.of(root, "webauditJ", "watch");
  }

  Map<String, Object> load() throws IOException {
    if (reset || !Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return null;
    try {
      regular(path);
      byte[] bytes;
      try (var in = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
        bytes = in.readNBytes(MAX_BYTES + 1);
      }
      if (bytes.length > MAX_BYTES) throw new IOException("state exceeds 32 MiB");
      var env = Json.object(new String(bytes, StandardCharsets.UTF_8));
      String data = Json.string(env.get("data"));
      if (Json.number(env.get("schema")) != 1
          || !key.equals(env.get("key"))
          || !targets.equals(env.get("targets"))
          || !WatchEngine.hash(data).equals(env.get("checksum")))
        throw new IOException("incompatible state");
      return Json.object(data);
    } catch (IOException | RuntimeException ex) {
      throw new IOException("invalid watch state; use --reset-state", ex);
    }
  }

  void save(Map<String, Object> state) throws IOException {
    String data = Json.string(state);
    byte[] bytes =
        Json.string(
                Json.map(
                    "schema",
                    1,
                    "key",
                    key,
                    "targets",
                    targets,
                    "checksum",
                    WatchEngine.hash(data),
                    "data",
                    data))
            .getBytes(StandardCharsets.UTF_8);
    if (bytes.length > MAX_BYTES) throw new IOException("state exceeds 32 MiB");
    Path temp = path.getParent().resolve(".state-" + UUID.randomUUID() + ".tmp");
    ManagedFiles.createFile(temp);
    try {
      try (var out = FileChannel.open(temp, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
        ByteBuffer b = ByteBuffer.wrap(bytes);
        while (b.hasRemaining()) out.write(b);
        out.force(true);
      }
      regular(path);
      Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
      if (!Main.os().equals("windows"))
        try (var directory = FileChannel.open(path.getParent(), StandardOpenOption.READ)) {
          directory.force(true);
        }
    } finally {
      Files.deleteIfExists(temp);
    }
  }

  public void close() throws IOException {
    try {
      if (lock != null) lock.release();
    } finally {
      if (channel != null) channel.close();
    }
  }
}
