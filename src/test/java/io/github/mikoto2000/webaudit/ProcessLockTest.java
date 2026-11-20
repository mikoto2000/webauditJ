package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

class ProcessLockTest {
  @TempDir Path dir;

  public static final class Holder {
    public static void main(String[] args) throws Exception {
      try (var lock = GeoStore.lock(Path.of(args[0]))) {
        System.out.println("LOCKED");
        System.out.flush();
        System.in.read();
      }
    }
  }

  @Test
  @Timeout(20)
  void excludesOtherProcessesAndRecoversAfterForcedExit() throws Exception {
    String java =
        Path.of(
                System.getProperty("java.home"),
                "bin",
                Main.os().equals("windows") ? "java.exe" : "java")
            .toString();
    Process child =
        new ProcessBuilder(
                java,
                "-cp",
                System.getProperty(
                    "surefire.test.class.path", System.getProperty("java.class.path")),
                Holder.class.getName(),
                dir.toString())
            .redirectErrorStream(true)
            .start();
    try {
      var ready =
          CompletableFuture.supplyAsync(() -> {
            try {
              return child.inputReader().readLine();
            } catch (IOException e) {
              throw new UncheckedIOException(e);
            }
          });
      assertEquals("LOCKED", ready.get(10, TimeUnit.SECONDS));
      assertThrows(IOException.class, () -> GeoStore.lock(dir));
    } finally {
      child.destroyForcibly();
      assertTrue(child.waitFor(5, TimeUnit.SECONDS));
    }
    try (var lock = GeoStore.lock(dir)) {
      assertNotNull(lock);
    }
  }
}
