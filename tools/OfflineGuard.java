import static java.lang.foreign.ValueLayout.*;

import java.lang.foreign.*;
import java.lang.instrument.Instrumentation;
import java.net.*;
import java.time.ZoneId;
import java.util.*;

/** Test-only Linux amd64 agent. It is never part of the application JAR. */
public final class OfflineGuard {
  public static void premain(String argument, Instrumentation instrumentation) throws Throwable {
    // JVM/libc initialization can access local nscd and probe IP capabilities.
    // Initialize these facilities before filtering every JVM thread, before app main.
    InetAddress.ofLiteral("127.0.0.1");
    InetAddress.ofLiteral("::1");
    ZoneId.systemDefault();
    var linker = Linker.nativeLinker();
    var prctl =
        linker.downcallHandle(
            linker.defaultLookup().find("prctl").orElseThrow(),
            FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG),
            Linker.Option.firstVariadicArg(1));
    var syscall =
        linker.downcallHandle(
            linker.defaultLookup().find("syscall").orElseThrow(),
            FunctionDescriptor.of(JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG),
            Linker.Option.firstVariadicArg(1));
    var instructions = new ArrayList<int[]>();
    instructions.add(new int[] {0x20, 0, 0, 4});
    instructions.add(new int[] {0x15, 1, 0, 0xc000003e});
    instructions.add(new int[] {0x06, 0, 0, 0x80000000});
    instructions.add(new int[] {0x20, 0, 0, 0});
    var denied = new ArrayList<Integer>();
    for (int number = 41; number <= 55; number++) denied.add(number);
    denied.addAll(List.of(288, 299, 307, 425, 426, 427));
    for (int number : denied) {
      instructions.add(new int[] {0x15, 0, 1, number});
      instructions.add(new int[] {0x06, 0, 0, 0x80000000});
    }
    instructions.add(new int[] {0x06, 0, 0, 0x7fff0000});
    try (var arena = Arena.ofConfined()) {
      var filters = arena.allocate(instructions.size() * 8L, 8);
      for (int i = 0; i < instructions.size(); i++) {
        int[] row = instructions.get(i);
        filters.set(JAVA_SHORT, i * 8L, (short) row[0]);
        filters.set(JAVA_BYTE, i * 8L + 2, (byte) row[1]);
        filters.set(JAVA_BYTE, i * 8L + 3, (byte) row[2]);
        filters.set(JAVA_INT, i * 8L + 4, row[3]);
      }
      var program = arena.allocate(16, 8);
      program.set(JAVA_SHORT, 0, (short) instructions.size());
      program.set(ADDRESS, 8, filters);
      int noNewPrivileges = (int) prctl.invokeExact(38, 1L, 0L, 0L, 0L);
      // SYS_seccomp, SET_MODE_FILTER, FLAG_TSYNC: apply to all existing JVM threads.
      long applied = (long) syscall.invokeExact(317L, 1L, 1L, program.address());
      if (noNewPrivileges != 0 || applied != 0) {
        throw new IllegalStateException("Cannot install synchronized network filter: " + applied);
      }
    }
    if ("probe".equals(argument)) {
      try (var socket = new Socket()) {
        socket.connect(new InetSocketAddress("127.0.0.1", 9));
      }
      throw new AssertionError("Network guard did not stop socket creation");
    }
  }
}
