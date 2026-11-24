package io.github.mikoto2000.webaudit;

import com.google.re2j.Pattern;
import java.util.*;

/** Post-detection presentation transform; source evidence and identifiers remain unchanged. */
final class BundleMask {
  private static final Pattern QUERY =
      Pattern.compile(
          "(?i)((?:[?&;]|%3f|%26)(?:access_token|api[_-]?key|token|password|passwd|secret|session(?:id|_id)?|authorization|cookie)(?:=|%3d))([^&\\s\"'<>]+)");
  private static final Pattern PAIR =
      Pattern.compile(
          "(?i)(\\b(?:access_token|api[_-]?key|token|password|passwd|secret|session(?:id|_id)?)=)([^&\\s\"'<>]+)");
  private static final Pattern HEADER =
      Pattern.compile(
          "(?i)((?:cookie|set-cookie|authorization|proxy-authorization)\\s*:\\s*)([^\"\\r\\n]*)");
  private static final Pattern SECRET_JSON =
      Pattern.compile(
          "(?i)(\"(?:http_)?(?:authorization|cookie|set_cookie|access_token|api_key|password|token|session_id)\"\\s*:\\s*)(\"(?:[^\"\\\\]|\\\\.)*\"|[^,}\\s]+)");
  private static final Pattern BEARER =
      Pattern.compile("(?i)\\b(Bearer|Basic)\\s+[A-Za-z0-9._~+/=-]+");

  static String controls(String value) {
    var out = new StringBuilder();
    value
        .codePoints()
        .forEach(cp -> {
          if (Character.getType(cp) == Character.CONTROL
              || cp == 0x061c
              || cp == 0x200e
              || cp == 0x200f
              || cp >= 0x202a && cp <= 0x202e
              || cp >= 0x2066 && cp <= 0x2069)
            out.append(String.format(Locale.ROOT, "\\u%04X", cp));
          else out.appendCodePoint(cp);
        });
    return out.toString();
  }

  static String text(String value, boolean redact) {
    String s = controls(value);
    if (!redact) return s;
    s = SECRET_JSON.matcher(s).replaceAll("$1\"[REDACTED]\"");
    s = QUERY.matcher(s).replaceAll("$1[REDACTED]");
    s = PAIR.matcher(s).replaceAll("$1[REDACTED]");
    s = HEADER.matcher(s).replaceAll("$1[REDACTED]");
    return BEARER.matcher(s).replaceAll("$1 [REDACTED]");
  }

  static boolean trusted(String key) {
    return Set.of("pattern", "filter", "condition", "conditions").contains(key);
  }

  static Object tree(Object value, boolean redact) {
    if (value instanceof String s) return text(s, redact);
    if (value instanceof Map<?, ?> map) {
      var out = new LinkedHashMap<String, Object>();
      for (var entry : map.entrySet()) {
        String key = entry.getKey().toString();
        out.put(key, trusted(key) ? entry.getValue() : tree(entry.getValue(), redact));
      }
      return out;
    }
    if (value instanceof Collection<?> values) {
      var out = new ArrayList<Object>();
      for (Object item : values) out.add(tree(item, redact));
      return out;
    }
    return value;
  }

  static String csv(String value, String header, boolean redact) {
    if (trusted(header)) return value;
    if (header.endsWith("_json"))
      try {
        return Json.MAPPER.writeValueAsString(tree(Json.object(value), redact));
      } catch (RuntimeException ignored) {
      }
    return text(value, redact);
  }
}
