package io.github.mikoto2000.webaudit;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

final class InputProgressDisplay implements Consumer<InputProgress> {
  private final Writer out;
  private final LongSupplier now;
  private long last;
  private int lastFiles = -1;

  InputProgressDisplay(Writer out) {
    this(out, System::nanoTime);
  }

  InputProgressDisplay(Writer out, LongSupplier now) {
    this.out = out;
    this.now = now;
  }

  @Override
  public void accept(InputProgress p) {
    long t = now.getAsLong();
    if (p.completedFiles() == lastFiles && t - last < 100_000_000L) return;
    last = t;
    lastFiles = p.completedFiles();
    int filled = p.totalFiles() > 0 ? 20 * p.completedFiles() / p.totalFiles() : 20;
    try {
      out.write(
          "\rInput files ["
              + "=".repeat(filled)
              + " ".repeat(20 - filled)
              + "] "
              + p.completedFiles()
              + "/"
              + p.totalFiles()
              + " files, "
              + p.lines()
              + " lines");
      if (p.completedFiles() == p.totalFiles()) out.write('\n');
      out.flush();
    } catch (IOException ex) {
      throw new UncheckedIOException(ex);
    }
  }
}
