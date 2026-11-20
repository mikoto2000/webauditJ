package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class DatabaseManagerTest {
  @TempDir Path dir;

  static final class Fake implements GeoSource {
    String version = "2026-11", failRole = "";
    int latest, fetch;

    public Release latest(String role, long deadline) throws IOException {
      latest++;
      try {
        return new Release(
            role,
            version,
            "https://download.db-ip.com/free/dbip-" + role + "-lite-" + version + ".mmdb.gz",
            HexFormat.of()
                .formatHex(
                    MessageDigest.getInstance("SHA-1")
                        .digest(Files.readAllBytes(Path.of(GeoIPTest.db(role))))));
      } catch (Exception ex) {
        throw new IOException(ex);
      }
    }

    public void fetch(Release r, OutputStream out, long deadline) throws IOException {
      fetch++;
      if (r.role().equals(failRole)) throw new IOException("injected transfer failure");
      try {
        var z = new GZIPOutputStream(out);
        z.write(Files.readAllBytes(Path.of(GeoIPTest.db(r.role()))));
        z.finish();
      } catch (Exception ex) {
        throw new IOException(ex);
      }
    }
  }

  @Test
  void installsPairWithoutRedownloadingAndChecksForUpdates() throws Exception {
    var fake = new Fake();
    var m = new DatabaseManager(dir, fake);
    var r = m.reconcile(false);
    assertEquals(List.of("country", "asn"), r.changed());
    assertEquals(2, fake.fetch);
    assertNotNull(GeoStore.withCurrent(dir, meta -> meta));
    m.reconcile(false);
    assertEquals(2, fake.latest);
    assertEquals(2, fake.fetch);
    r = m.reconcile(true);
    assertTrue(r.changed().isEmpty());
    assertEquals(2, fake.fetch);
  }

  @Test
  void failuresAtEveryPublicationBoundaryPreserveOldManifest() throws Exception {
    var fake = new Fake();
    var m = new DatabaseManager(dir, fake);
    m.reconcile(false);
    byte[] before = Files.readAllBytes(dir.resolve("metadata.json"));
    fake.version = "2026-12";
    for (String point :
        List.of(
            "after-country",
            "after-asn",
            "after-generation",
            "manifest-write",
            "manifest-replace")) {
      m.fault =
          p -> {
            if (p.equals(point)) throw new IOException(point);
          };
      assertThrows(IOException.class, () -> m.reconcile(true), point);
      assertArrayEquals(before, Files.readAllBytes(dir.resolve("metadata.json")), point);
      GeoStore.withCurrent(dir, meta -> meta);
    }
    m.fault = p -> {};
    assertEquals(2, m.reconcile(true).changed().size());
  }

  @Test
  void failedSecondTransferAndSizeLimitDoNotPublishPartialPair() throws Exception {
    var fake = new Fake();
    var m = new DatabaseManager(dir, fake);
    fake.failRole = "asn";
    assertThrows(IOException.class, () -> m.reconcile(false));
    assertFalse(Files.exists(dir.resolve("metadata.json")));
    fake.failRole = "";
    m.maxDatabase = 10;
    assertThrows(IOException.class, () -> m.reconcile(false));
    assertFalse(Files.exists(dir.resolve("metadata.json")));
  }

  @Test
  void rollbackRestoresPreviousPairAndRejectsTamperedPaths() throws Exception {
    var fake = new Fake();
    var m = new DatabaseManager(dir, fake);
    String first = Json.string(Json.obj(m.reconcile(false).metadata().get("current")).get("id"));
    fake.version = "2026-12";
    m.reconcile(true);
    m.rollback();
    assertEquals(
        first,
        GeoStore.withCurrent(dir, meta -> Json.string(Json.obj(meta.get("current")).get("id"))));
    var data = Json.object(Files.readString(dir.resolve("metadata.json")));
    Json.rows(Json.obj(data.get("current")).get("databases"))
        .getFirst()
        .put("file", "../escape.mmdb");
    Files.writeString(dir.resolve("metadata.json"), Json.MAPPER.writeValueAsString(data));
    assertThrows(IOException.class, () -> GeoStore.withCurrent(dir, meta -> meta));
  }

  @Test
  void excludesConcurrentWriterAndReleasesAfterClose() throws Exception {
    try (var lock = GeoStore.lock(dir)) {
      assertThrows(IOException.class, () -> GeoStore.lock(dir));
    }
    try (var lock = GeoStore.lock(dir)) {
      assertNotNull(lock);
    }
  }

  @Test
  void reclaimsInterruptedStageAndOrphanGeneration() throws Exception {
    Files.createDirectory(dir.resolve(".staging-abandoned"));
    Files.createDirectories(dir.resolve("versions/gen-orphan"));
    var m = new DatabaseManager(dir, new Fake());
    m.reconcile(false);
    assertFalse(Files.exists(dir.resolve(".staging-abandoned")));
    assertFalse(Files.exists(dir.resolve("versions/gen-orphan")));
  }
}
