package io.github.mikoto2000.webaudit;

import com.maxmind.db.Reader;
import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;

final class GeoStore {
  static final class NotInstalled extends IOException {
    NotInstalled() {
      super("GeoIP databases are not installed; run 'webauditJ geoip download'");
    }
  }

  interface LockedRead<T> {
    T read(Map<String, Object> metadata) throws IOException;
  }

  static final com.google.re2j.Pattern GENERATION =
      com.google.re2j.Pattern.compile("^gen-[a-zA-Z0-9_-]{1,80}$");

  static final class Lock implements AutoCloseable {
    private final FileChannel channel;
    private final FileLock lock;

    Lock(FileChannel channel, FileLock lock) {
      this.channel = channel;
      this.lock = lock;
    }

    public void close() throws IOException {
      try {
        lock.release();
      } finally {
        channel.close();
      }
    }
  }

  static void safe(Path dir) throws IOException {
    for (String name : List.of("versions", ".lock", "metadata.json"))
      if (Files.isSymbolicLink(dir.resolve(name)))
        throw new IOException("GeoIP managed " + name + " must not be a symlink");
  }

  static Lock lock(Path dir) throws IOException {
    safe(dir);
    Path path = dir.resolve(".lock");
    if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS))
      try {
        ManagedFiles.createFile(path);
      } catch (FileAlreadyExistsException ignored) {
      }
    var channel = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE);
    try {
      FileLock lock = channel.tryLock(0, 1, false);
      if (lock == null)
        throw new IOException("another GeoIP writer is running (retry after it exits)");
      return new Lock(channel, lock);
    } catch (IOException | OverlappingFileLockException ex) {
      channel.close();
      throw new IOException("another GeoIP writer is running (retry after it exits)", ex);
    }
  }

  static Map<String, Object> read(Path dir) throws IOException {
    try (var in = Files.newInputStream(dir.resolve("metadata.json"))) {
      byte[] data = in.readNBytes((1 << 20) + 1);
      if (data.length > 1 << 20) throw new IOException("GeoIP metadata exceeds size limit");
      var m = Json.object(new String(data, java.nio.charset.StandardCharsets.UTF_8));
      if (Json.number(m.get("format")) != 1)
        throw new IOException("unsupported GeoIP metadata format");
      return m;
    } catch (NoSuchFileException ex) {
      throw new NotInstalled();
    } catch (RuntimeException ex) {
      throw new IOException("GeoIP metadata is corrupt", ex);
    }
  }

  static <T> T withCurrent(Path dir, LockedRead<T> consume) throws IOException {
    if (!Files.exists(dir.resolve("metadata.json"), LinkOption.NOFOLLOW_LINKS))
      throw new NotInstalled();
    safe(dir);
    try (var lock = lock(dir)) {
      var m = read(dir);
      validate(dir, Json.obj(m.get("current")));
      return consume.read(m);
    } catch (RuntimeException ex) {
      throw new IOException("GeoIP metadata is corrupt", ex);
    }
  }

  static void validate(Path dir, Map<String, Object> generation) throws IOException {
    try {
      String id = Json.string(generation.get("id"));
      var databases = Json.rows(generation.get("databases"));
      if (!GENERATION.matcher(id).matches() || databases.size() != 2)
        throw new IOException("invalid GeoIP generation metadata");
      for (int i = 0; i < 2; i++) {
        String role = i == 0 ? "country" : "asn";
        var d = databases.get(i);
        String expected = "versions/" + id + "/" + role + ".mmdb",
            sum = Json.string(d.get("sha256"));
        if (!role.equals(d.get("role"))
            || !expected.equals(d.get("file"))
            || Json.number(d.get("size")) <= 0
            || sum.length() != 64
            || HexFormat.of().parseHex(sum).length != 32)
          throw new IOException("invalid GeoIP " + role + " metadata/path");
        String url = Json.string(d.get("url"));
        DBIPProvider.allowed(url);
        var release = DBIPProvider.DOWNLOAD_PATH.matcher(java.net.URI.create(url).getPath());
        if (!release.matches()
            || !role.equals(release.group(1))
            || !release.group(2).equals(d.get("version"))
            || !"DB-IP Lite".equals(d.get("provider"))
            || d.get("downloaded_at") == null)
          throw new IOException("GeoIP publication metadata mismatch");
        Times.parse((String) d.get("downloaded_at"));
        Path path = dir.resolve(expected);
        for (Path p : List.of(dir.resolve("versions"), dir.resolve("versions").resolve(id), path))
          if (Files.isSymbolicLink(p))
            throw new IOException("GeoIP managed path is a symlink: " + p);
        var info = inspect(path, role);
        for (String key : List.of("size", "sha256", "type", "source_sha1"))
          if (!Objects.equals(Json.string(info.get(key)), Json.string(d.get(key))))
            throw new IOException("GeoIP " + role + " integrity mismatch (size/SHA256/type/build)");
        if (!sameTime(info.get("build_time"), d.get("build_time")))
          throw new IOException("GeoIP build time mismatch");
      }
    } catch (RuntimeException ex) {
      throw new IOException("invalid GeoIP generation metadata", ex);
    }
  }

  private static boolean sameTime(Object a, Object b) {
    if (a == null || b == null) return a == b;
    return Times.parse((String) a).toInstant().equals(Times.parse((String) b).toInstant());
  }

  static Map<String, Object> inspect(Path path, String role) throws IOException {
    long size = Files.size(path);
    if (!Files.isRegularFile(path) || size > 256L << 20)
      throw new IOException("GeoIP file is not a regular MMDB within size limit");
    MessageDigest sha256, sha1;
    try {
      sha256 = MessageDigest.getInstance("SHA-256");
      sha1 = MessageDigest.getInstance("SHA-1");
    } catch (NoSuchAlgorithmException ex) {
      throw new AssertionError(ex);
    }
    try (var input = Files.newInputStream(path)) {
      byte[] bytes = new byte[65536];
      int n;
      while ((n = input.read(bytes)) != -1) {
        sha256.update(bytes, 0, n);
        sha1.update(bytes, 0, n);
      }
    }
    try (var db = new Reader(path.toFile(), GeoIP.readerMode())) {
      String type = db.getMetadata().databaseType(),
          expected =
              role.equals("country")
                  ? "DBIP-Country-Lite"
                  : role.equals("asn") ? "DBIP-ASN-Lite" : "";
      if (expected.isEmpty() || !type.equals(expected) && !type.startsWith(expected + " ("))
        throw new IOException("expected " + role + " database, got " + type);
      boolean found = false;
      var networks = db.networks(Map.class);
      while (networks.hasNext()) {
        Map<?, ?> r = networks.next().data();
        if (r == null) continue;
        if (role.equals("country")) {
          Object country = r.get("country");
          if (country != null && !(country instanceof Map))
            throw new IOException("invalid country schema");
          if (country instanceof Map<?, ?> c) {
            Object code = c.get("iso_code"), names = c.get("names");
            if (code != null && !(code instanceof String)
                || names != null && !(names instanceof Map))
              throw new IOException("invalid country schema");
            if (names instanceof Map<?, ?> m)
              for (Object value : m.values())
                if (!(value instanceof String)) throw new IOException("invalid country names");
            found |= code != null || names instanceof Map<?, ?> m && !m.isEmpty();
          }
        } else {
          Object number = r.get("autonomous_system_number"),
              org = r.get("autonomous_system_organization");
          if (number != null
                  && (!(number instanceof Number)
                      || number instanceof Float
                      || number instanceof Double
                      || ((Number) number).longValue() < 0
                      || ((Number) number).longValue() > 0xffffffffL)
              || org != null && !(org instanceof String))
            throw new IOException("invalid ASN schema");
          found |= number != null || org != null;
        }
      }
      if (!found) throw new IOException("GeoIP " + role + " database contains no expected fields");
      return Json.map(
          "role",
          role,
          "provider",
          "DB-IP Lite",
          "type",
          type,
          "build_time",
          db.getMetadata().buildEpoch().signum() > 0
              ? Times.instant(db.getMetadata().buildTime())
              : null,
          "size",
          size,
          "sha256",
          HexFormat.of().formatHex(sha256.digest()),
          "source_sha1",
          HexFormat.of().formatHex(sha1.digest()));
    } catch (IOException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new IOException("GeoIP " + role + " MMDB validation", ex);
    }
  }
}
