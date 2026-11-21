package io.github.mikoto2000.webaudit;

import static java.lang.foreign.ValueLayout.*;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.Path;
import java.util.*;

/** Small OS boundary for file IDs and hook process containment. No network or third-party DLL. */
final class WatchNative {
  static final boolean WINDOWS = Main.os().equals("windows");
  static final Linker LINKER = Linker.nativeLinker();
  static final SymbolLookup SYMBOLS =
      WINDOWS ? SymbolLookup.libraryLookup("kernel32", Arena.global()) : LINKER.defaultLookup();

  static MethodHandle function(String name, MemoryLayout result, MemoryLayout... args) {
    return LINKER.downcallHandle(
        SYMBOLS.find(name).orElseThrow(), FunctionDescriptor.of(result, args));
  }

  static Object call(String name, MemoryLayout result, MemoryLayout[] args, Object... values)
      throws IOException {
    try {
      return function(name, result, args).invokeWithArguments(values);
    } catch (Throwable ex) {
      throw new IOException("native watch operation failed: " + name, ex);
    }
  }

  static void closeHandle(MemorySegment handle) throws IOException {
    if (handle != null && !handle.equals(MemorySegment.NULL))
      call("CloseHandle", JAVA_INT, new MemoryLayout[] {ADDRESS}, handle);
  }

  static String fileID(Path path) throws IOException {
    try (var arena = Arena.ofConfined()) {
      char[] chars = (path.toString() + "\0").toCharArray();
      var name = arena.allocateFrom(JAVA_CHAR, chars);
      var h =
          (MemorySegment)
              call(
                  "CreateFileW",
                  ADDRESS,
                  new MemoryLayout[] {
                    ADDRESS, JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, ADDRESS
                  },
                  name,
                  0,
                  7,
                  MemorySegment.NULL,
                  3,
                  0,
                  MemorySegment.NULL);
      if (h.address() == -1) throw new IOException("cannot obtain file identity: " + path);
      try {
        var info = arena.allocate(52, 4);
        int ok =
            (int)
                call(
                    "GetFileInformationByHandle",
                    JAVA_INT,
                    new MemoryLayout[] {ADDRESS, ADDRESS},
                    h,
                    info);
        if (ok == 0) throw new IOException("cannot read file identity: " + path);
        return Integer.toUnsignedString(info.get(JAVA_INT, 28))
            + ":"
            + Integer.toUnsignedString(info.get(JAVA_INT, 44))
            + ":"
            + Integer.toUnsignedString(info.get(JAVA_INT, 48));
      } finally {
        closeHandle(h);
      }
    }
  }

  static MemorySegment job(Process p) throws IOException {
    var job =
        (MemorySegment)
            call(
                "CreateJobObjectW",
                ADDRESS,
                new MemoryLayout[] {ADDRESS, ADDRESS},
                MemorySegment.NULL,
                MemorySegment.NULL);
    if (job.equals(MemorySegment.NULL)) throw new IOException("cannot create hook job");
    try (var arena = Arena.ofConfined()) {
      // JOBOBJECT_EXTENDED_LIMIT_INFORMATION, Windows 64-bit ABI (amd64/arm64).
      if (ADDRESS.byteSize() != 8) throw new IOException("hook jobs require a 64-bit JVM");
      var info = arena.allocate(144, 8);
      info.set(JAVA_INT, 16, 0x2000); // KILL_ON_JOB_CLOSE
      int ok =
          (int)
              call(
                  "SetInformationJobObject",
                  JAVA_INT,
                  new MemoryLayout[] {ADDRESS, JAVA_INT, ADDRESS, JAVA_INT},
                  job,
                  9,
                  info,
                  144);
      if (ok == 0) throw new IOException("cannot configure hook job");
      var process =
          (MemorySegment)
              call(
                  "OpenProcess",
                  ADDRESS,
                  new MemoryLayout[] {JAVA_INT, JAVA_INT, JAVA_INT},
                  0x101,
                  0,
                  (int) p.pid());
      if (process.equals(MemorySegment.NULL)) throw new IOException("cannot open hook helper");
      try {
        ok =
            (int)
                call(
                    "AssignProcessToJobObject",
                    JAVA_INT,
                    new MemoryLayout[] {ADDRESS, ADDRESS},
                    job,
                    process);
        if (ok == 0) throw new IOException("cannot contain hook helper in job");
      } finally {
        closeHandle(process);
      }
      return job;
    } catch (IOException | RuntimeException ex) {
      closeHandle(job);
      throw ex;
    }
  }

  static void session() throws IOException {
    if ((int) call("setsid", JAVA_INT, new MemoryLayout[] {}) < 0)
      throw new IOException("cannot create hook process group");
  }

  static void killGroup(long pid) throws IOException {
    call("kill", JAVA_INT, new MemoryLayout[] {JAVA_INT, JAVA_INT}, -(int) pid, 9);
  }
}
