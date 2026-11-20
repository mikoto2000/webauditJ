package io.github.mikoto2000.webaudit;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

final class Core {
  private Core() {}

  static boolean space(int cp) {
    return cp >= 9 && cp <= 13
        || cp == 0x20
        || cp == 0x85
        || cp == 0xa0
        || cp == 0x1680
        || cp >= 0x2000 && cp <= 0x200a
        || cp == 0x2028
        || cp == 0x2029
        || cp == 0x202f
        || cp == 0x205f
        || cp == 0x3000;
  }

  static String s(String value) {
    return Objects.requireNonNullElse(value, "");
  }

  static byte[] sha(byte[] b) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(b);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  static String digest(String s) {
    return new String(sha(s.getBytes(StandardCharsets.UTF_8)), StandardCharsets.ISO_8859_1);
  }

  static String id(String digest) {
    return "WA-"
        + HexFormat.of().formatHex(sha(digest.getBytes(StandardCharsets.ISO_8859_1)), 0, 8);
  }

  static void unique(List<String> list, String s) {
    if (!list.contains(s)) list.add(s);
  }

  static Object nullable(List<?> list) {
    return list.isEmpty() ? null : list;
  }

  static int size(String s) {
    return s == null ? 0 : s.getBytes(StandardCharsets.UTF_8).length;
  }

  static String clip(String s, int max) {
    if (s == null || size(s) <= max) return s;
    byte[] b = s.getBytes(StandardCharsets.UTF_8);
    int n = max;
    while (n > 0 && (b[n] & 0xc0) == 0x80) n--;
    return new String(b, 0, n, StandardCharsets.UTF_8);
  }

  static Event compact(Event original) {
    Event e = original.copy();
    e.sourceRequest = clip(e.sourceRequest, 4096);
    e.recordedUA = clip(e.recordedUA, 512);
    e.recordedReferer = clip(e.recordedReferer, 512);
    e.rawRequest = clip(e.rawRequest, 4096);
    e.envelope = clip(e.envelope, 1024);
    e.suffix = clip(e.suffix, 1024);
    e.raw = clip(e.raw, 4096);
    e.target = clip(e.target, 4096);
    e.path = clip(e.path, 1024);
    e.ua = clip(e.ua, 512);
    e.host = clip(e.host, 255);
    e.referer = clip(e.referer, 512);
    e.query = clip(e.query, 2048);
    e.method = clip(e.method, 32);
    e.protocol = clip(e.protocol, 32);
    e.evidenceTruncated = original.evidenceTruncated || !e.toMap().equals(original.toMap());
    return e;
  }

  static Normalizer.Normalized compact(Normalizer.Normalized n) {
    var bytes = n.rawVariants().stream().map(v -> clipDecodedBytes(v, 1024)).toList();
    return new Normalizer.Normalized(clip(n.original(), 4096),
        bytes.stream().map(Utf8::decode).toList(), n.steps(), n.warnings(), bytes);
  }

  private static byte[] clipDecodedBytes(byte[] bytes, int max) {
    if (bytes.length <= max) return bytes;
    var input = java.nio.ByteBuffer.wrap(bytes, 0, max);
    var output = java.nio.CharBuffer.allocate(max);
    var decoder = StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT);
    var result = decoder.decode(input, output, true);
    return Arrays.copyOf(bytes, result.isError() ? input.position() : max);
  }

  static Map<String, Object> normalized(Normalizer.Normalized n) {
    return Json.map(
        "original",
        n.original(),
        "variants",
        n.variants(),
        "steps",
        nullable(n.steps()),
        "warnings",
        nullable(n.warnings()));
  }

  static int evidenceSize(Event e, Normalizer.Normalized n) {
    int total =
        size(e.raw)
            + size(e.target)
            + size(e.path)
            + size(e.query)
            + size(e.ua)
            + size(e.host)
            + size(e.referer)
            + size(n.original());
    total +=
        size(e.rawRequest)
            + size(e.envelope)
            + size(e.suffix)
            + size(e.wallTime)
            + size(e.sourceRequest)
            + size(e.recordedUA)
            + size(e.recordedReferer);
    return total + n.rawVariants().stream().mapToInt(v -> v.length).sum();
  }

  static int weight(String severity) {
    return switch (severity) {
      case "critical" -> 40;
      case "high" -> 30;
      case "medium" -> 15;
      default -> 5;
    };
  }

  static Map<String, Object> behaviorRule(String id, String description) {
    return Json.map(
        "id",
        id,
        "category",
        id.startsWith("WB-") ? id.substring(3) : id,
        "severity",
        "medium",
        "description",
        description,
        "required",
        List.of("ip", "time"),
        "pattern",
        "",
        "field",
        "",
        "source",
        "docs/rule-inventory.md");
  }
}
