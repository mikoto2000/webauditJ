package io.github.mikoto2000.webaudit;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Private launcher protocol: wait for containment before starting any user executable. */
public final class WatchHookChild {
  private WatchHookChild() {}

  public static void main(String[] args) throws Exception {
    if (!Main.os().equals("windows")) WatchNative.session();
    System.out.write("READY\n".getBytes(StandardCharsets.US_ASCII));
    System.out.flush();
    // The parent releases this gate only after the Job Object is attached (Windows).
    byte[] input = System.in.readNBytes(131073);
    if (input.length > 131072) System.exit(2);
    var config = Json.object(new String(input, StandardCharsets.UTF_8));
    var command =
        new ArrayList<>(((List<?>) config.get("command")).stream().map(Object::toString).toList());
    if (Main.os().equals("windows")) {
      // Encode CRT argv explicitly: the JDK legacy path otherwise loses embedded quotes.
      // This property affects only this isolated launcher JVM.
      System.setProperty("jdk.lang.Process.allowAmbiguousCommands", "true");
      String executable = command.getFirst().toLowerCase(Locale.ROOT);
      if (executable.endsWith(".cmd")
          || executable.endsWith(".bat")
          || executable.indexOf('"') >= 0)
        throw new IOException("hook requires an executable, not a batch command");
      for (int i = 1; i < command.size(); i++) command.set(i, windowsArgument(command.get(i)));
    }
    var p =
        new ProcessBuilder(command)
            .redirectOutput(ProcessBuilder.Redirect.INHERIT)
            .redirectError(ProcessBuilder.Redirect.INHERIT)
            .start();
    try (var out = p.getOutputStream()) {
      out.write(Base64.getDecoder().decode(Json.string(config.get("payload"))));
    }
    System.exit(p.waitFor());
  }

  static String windowsArgument(String value) {
    StringBuilder b = new StringBuilder("\"");
    int slashes = 0;
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c == '\\') {
        slashes++;
        continue;
      }
      if (c == '"') b.append("\\".repeat(slashes * 2 + 1)).append(c);
      else b.append("\\".repeat(slashes)).append(c);
      slashes = 0;
    }
    return b.append("\\".repeat(slashes * 2)).append('"').toString();
  }
}
