package io.github.mikoto2000.webaudit;

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import java.util.*;

final class LogLayouts {
  private LogLayouts() {}

  private static final Map<String, Pattern> PATTERNS = new HashMap<>();

  static {
    Json.obj(Json.resource("parser-patterns.json"))
        .forEach((k, v) -> PATTERNS.put(k, Pattern.compile((String) v)));
  }

  static Pattern pattern(String name) {
    return PATTERNS.get(name);
  }

  static Matcher match(String name, String s) {
    var m = pattern(name).matcher(s);
    return m.find() ? m : null;
  }

  static Map<String, String> fields(Pattern p, String s) {
    var m = p.matcher(s);
    if (!m.find()) return null;
    var f = new HashMap<String, String>();
    p.namedGroups()
        .forEach((name, index) -> f.put(name, Objects.requireNonNullElse(m.group(index), "")));
    return f;
  }
}
