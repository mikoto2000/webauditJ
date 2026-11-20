package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.Flow;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RecoveryBoundariesTest {
  @TempDir Path dir;

  @Test
  void rollbackUsesValidatedPreviousGenerationWhenCurrentDatabaseIsCorrupt() throws Exception {
    var source = new DatabaseManagerTest.Fake();
    var manager = new DatabaseManager(dir, source);
    manager.reconcile(false);
    source.version = "2026-12";
    var current = Json.obj(manager.reconcile(true).metadata().get("current"));
    Files.writeString(
        dir.resolve((String) Json.rows(current.get("databases")).getFirst().get("file")), "broken");
    assertThrows(IOException.class, () -> GeoStore.withCurrent(dir, m -> m));
    manager.rollback();
    assertNotNull(GeoStore.withCurrent(dir, m -> m));
  }

  @Test
  void checksPublishedChecksumBeforeActivatingAnyDatabase() throws Exception {
    var fake = new DatabaseManagerTest.Fake();
    GeoSource corrupt =
        new GeoSource() {
          public Release latest(String role, long deadline) throws IOException {
            var r = fake.latest(role, deadline);
            return new Release(r.role(), r.version(), r.url(), "0".repeat(40));
          }

          public void fetch(Release release, OutputStream out, long deadline) throws IOException {
            fake.fetch(release, out, deadline);
          }
        };
    assertThrows(IOException.class, () -> new DatabaseManager(dir, corrupt).reconcile(false));
    assertFalse(Files.exists(dir.resolve("metadata.json")));
  }

  @Test
  void httpBodyEnforcesLimitBeforeWritingAndCancelsSubscription() throws Exception {
    var out = new ByteArrayOutputStream();
    var body = new LimitedHttpBody(out, 2);
    boolean[] cancelled = {false};
    body.onSubscribe(
        new Flow.Subscription() {
          public void request(long n) {}

          public void cancel() {
            cancelled[0] = true;
          }
        });
    body.onNext(List.of(ByteBuffer.wrap(new byte[] {1, 2, 3})));
    assertTrue(cancelled[0]);
    assertEquals(0, out.size());
    assertTrue(body.getBody().toCompletableFuture().isCompletedExceptionally());
  }

  @Test
  void expiredOperationNeverInvokesTransport() {
    int[] calls = {0};
    var provider =
        new DBIPProvider((uri, timeout, out, limit) -> {
          calls[0]++;
          return new DBIPProvider.Response(200, null);
        });
    assertThrows(IOException.class, () -> provider.latest("country", System.nanoTime() - 1));
    assertEquals(0, calls[0]);
  }
}
