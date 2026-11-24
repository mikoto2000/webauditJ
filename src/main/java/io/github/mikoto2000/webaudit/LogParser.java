package io.github.mikoto2000.webaudit;

import static io.github.mikoto2000.webaudit.LogLayouts.*;

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import java.time.*;
import java.util.*;

public final class LogParser {
  private LogParser() {}

  public static Event parse(String text, String file, long line, String custom) {
    try {
      return parseChecked(text, file, line, custom);
    } catch (IllegalArgumentException ex) {
      throw ex;
    } catch (RuntimeException ex) {
      throw new IllegalArgumentException(ex.getMessage(), ex);
    }
  }

  private static Event parseChecked(String text, String file, long line, String custom) {
    if (text.indexOf('\0') >= 0 || text.indexOf('\r') >= 0 || text.indexOf('\n') >= 0)
      throw new IllegalArgumentException("invalid UTF-8 or control line");
    String original = text, envelope = null;
    if (custom.isEmpty()) {
      String[] unwrapped = unwrap(text);
      text = unwrapped[0];
      envelope = unwrapped[1];
      Event error = parseError(text, original, file, line);
      if (error != null) {
        error.envelope = envelope;
        error.format = (envelope == null ? "" : "syslog/") + "http-error";
        return error;
      }
    }
    String format = "unknown";
    Map<String, String> f = null;
    if (!custom.isEmpty()) {
      var p = Pattern.compile(custom);
      if (!p.matcher(text).matches())
        throw new IllegalArgumentException("custom regex does not match whole line");
      f = fields(p, text);
      format = "custom-regex";
    } else if (text.stripLeading().startsWith("{")) {
      format = "nginx-json";
      var object = Json.object(text);
      f = new HashMap<>();
      if (object.get("request_time") != null)
        f.put("duration_seconds", Json.string(object.get("request_time")));
      var keys =
          Json.map(
              "remote_addr",
              "ip",
              "time_local",
              "time",
              "time_iso8601",
              "time",
              "request",
              "request",
              "status",
              "status",
              "body_bytes_sent",
              "bytes",
              "http_user_agent",
              "ua",
              "http_referer",
              "referer",
              "host",
              "host");
      for (var entry : keys.entrySet())
        if (object.get(entry.getKey()) != null) {
          String dest = (String) entry.getValue();
          if (f.containsKey(dest))
            throw new IllegalArgumentException("ambiguous JSON field " + dest);
          f.put(dest, Json.string(object.get(entry.getKey())));
        }
    } else {
      for (String name : List.of("standard", "extendedStandard", "npmPlus", "npmLegacy")) {
        f = fields(pattern(name), text);
        if (f != null) {
          format =
              switch (name) {
                case "standard" ->
                    f.get("ua") == null ? "apache-nginx-common" : "apache-nginx-combined";
                case "extendedStandard" -> "extended-combined";
                case "npmPlus" -> "npm-plus";
                default -> "npm-legacy";
              };
          break;
        }
      }
    }
    if (f == null)
      throw new IllegalArgumentException(
          "unrecognized layout; expected ip/time/request/status/bytes; use --log-regex with named"
              + " groups for custom fields");
    Event e = fromFields(f, original, file, line);
    if (f.get("duration_seconds") != null) {
      try {
        double value = Double.parseDouble(f.get("duration_seconds"));
        if (!Double.isFinite(value) || value < 0) e.invalidDuration = true;
        else e.duration = value;
      } catch (NumberFormatException ex) {
        e.invalidDuration = true;
      }
    }
    e.envelope = envelope;
    e.format = (envelope == null ? "" : "syslog/") + format;
    return e;
  }

  static Event fromFields(Map<String, String> f, String raw, String file, long line) {
    Event e = new Event();
    e.file = file;
    e.line = line;
    e.raw = raw;
    e.ip = f.getOrDefault("ip", "");
    if (f.containsKey("ua")) e.recordedUA = f.get("ua");
    if (f.containsKey("referer")) e.recordedReferer = f.get("referer");
    try {
      IP.parse(e.ip);
    } catch (IllegalArgumentException ex) {
      throw new IllegalArgumentException(
          "invalid/missing client IP (recognized time/request/status); hostnames and XFF not"
              + " trusted");
    }
    try {
      e.time = Times.parse(f.getOrDefault("time", ""));
    } catch (DateTimeException ex) {
      throw new IllegalArgumentException("invalid/missing timestamp");
    }
    String req = f.getOrDefault("request", "");
    if (!req.isEmpty()) {
      String[] parts = req.split(" ", -1);
      e.rawRequest = req;
      if (parts.length == 2
          && pattern("requestMethod").matcher(parts[0]).find()
          && !parts[1].isEmpty()) {
        f.put("method", parts[0]);
        f.put("target", parts[1]);
      } else if (parts.length != 3
          || !pattern("requestMethod").matcher(parts[0]).find()
          || parts[1].isEmpty()
          || !pattern("requestVersion").matcher(parts[2]).find()) e.malformed = true;
      else {
        f.put("method", parts[0]);
        f.put("target", parts[1]);
        f.put("protocol", parts[2]);
      }
    }
    e.target = f.getOrDefault("target", "");
    if ((e.target.isEmpty() || e.target.equals("-")) && !e.malformed)
      throw new IllegalArgumentException("missing request target");
    e.path = e.target;
    int q = e.target.indexOf('?');
    if (q >= 0) {
      e.path = e.target.substring(0, q);
      e.query = e.target.substring(q + 1);
    }
    e.suffix = optional(f, "suffix");
    e.host = optional(f, "host");
    e.method = optional(f, "method");
    e.protocol = optional(f, "protocol");
    e.ua = optional(f, "ua");
    e.referer = optional(f, "referer");
    String status = optional(f, "status");
    if (status != null) {
      e.status = Integer.valueOf(status);
      if (e.status < 100 || e.status > 599) throw new IllegalArgumentException("invalid status");
    }
    String bytes = optional(f, "bytes");
    if (bytes != null) {
      e.bytes = Long.valueOf(bytes);
      if (e.bytes < 0) throw new IllegalArgumentException("invalid response size");
    }
    return e;
  }

  private static String optional(Map<String, String> f, String key) {
    String s = f.get(key);
    return s == null || s.isEmpty() || s.equals("-") ? null : s;
  }

  private static String[] unwrap(String s) {
    if (s.startsWith("{")) {
      var obj = Json.object(s);
      String message = Json.string(obj.get("message"));
      if ("log.journald".equals(obj.get("type"))) {
        int i = message.indexOf(" nginx: ");
        if (i >= 0) return new String[] {message.substring(i + 8), "upsun/journald"};
      }
    }
    Matcher m = match("rfc3164", s);
    if (m != null) return new String[] {s.substring(m.end()), m.group()};
    m = match("rfc5424", s);
    if (m == null) return new String[] {s, null};
    int base = m.end(), i = base;
    if (i < s.length() && s.charAt(i) == '-') i++;
    else
      while (i < s.length() && s.charAt(i) == '[') {
        boolean quoted = false, escaped = false, closed = false;
        i++;
        while (i < s.length()) {
          char c = s.charAt(i++);
          if (escaped) {
            escaped = false;
            continue;
          }
          if (c == '\\') {
            escaped = true;
            continue;
          }
          if (c == '"') quoted = !quoted;
          if (c == ']' && !quoted) {
            closed = true;
            break;
          }
        }
        if (!closed) throw new IllegalArgumentException("unterminated syslog structured data");
      }
    if (i == base || i >= s.length() || s.charAt(i) != ' ')
      throw new IllegalArgumentException("invalid syslog structured data");
    return new String[] {s.substring(i + 1), s.substring(0, i + 1)};
  }

  private static Event parseError(String body, String raw, String file, long line) {
    LocalDateTime ts;
    String wall;
    Matcher m = match("nginxErrTime", body);
    boolean nginx = m != null;
    if (nginx) {
      wall = m.group(1);
      ts =
          LocalDateTime.parse(
              wall, java.time.format.DateTimeFormatter.ofPattern("uuuu/MM/dd HH:mm:ss"));
    } else {
      m = match("apacheErrTime", body);
      if (m == null) return null;
      wall = m.group(1);
      ts = LocalDateTime.parse(wall.substring(4).replaceAll(" +", " "), Times.APACHE_ERROR);
    }
    m = match("errorClient", body);
    if (m == null) throw new IllegalArgumentException("error log lacks client IP");
    String ip = Objects.requireNonNullElse(m.group(1), m.group(2));
    try {
      IP.parse(ip);
    } catch (IllegalArgumentException ex) {
      int end = ip.lastIndexOf(':');
      if (ip.startsWith("[") && ip.contains("]:")) ip = ip.substring(1, ip.indexOf("]:"));
      else if (end >= 0) {
        String candidate = ip.substring(0, end);
        IP.parse(candidate);
        ip = candidate;
      } else throw ex;
    }
    IP.parse(ip);
    String req = "", targetOnly = "", subType = "";
    m = match("errorReq", body);
    if (m != null) req = m.group(1);
    else {
      m = match("invalidURI", body);
      if (m != null) req = m.group(1).strip();
    }
    if (req.isEmpty()) {
      m = match("apacheAuth", body);
      if (m != null) {
        targetOnly = m.group(1);
        subType = "auth_fail";
      }
      m = match("apacheNotFound", body);
      if (m != null) {
        targetOnly = m.group(1);
        subType = "auth_fail";
      }
      m = match("apacheDenied", body);
      if (m != null) {
        targetOnly = m.group(1);
        subType = "permission_denied";
      }
    }
    if (req.isEmpty() && targetOnly.isEmpty() && nginx)
      throw new IllegalArgumentException(
          "Nginx entry lacks HTTP request; mail/stream logs require another parser");
    var f = new HashMap<String, String>();
    f.put("ip", ip);
    f.put("time", Times.text(ts.atOffset(ZoneOffset.UTC)));
    f.put("request", req);
    if (!targetOnly.isEmpty()) f.put("target", targetOnly);
    String[] parts = req.split(" ", -1);
    if (parts.length == 2) {
      f.put("method", parts[0]);
      f.put("target", parts[1]);
      f.put("request", "");
    }
    Event e;
    if (req.isEmpty() && targetOnly.isEmpty()) {
      e = new Event();
      e.ip = ip;
      e.time = ts.atOffset(ZoneOffset.UTC);
      e.file = file;
      e.line = line;
      e.raw = raw;
    } else e = fromFields(f, raw, file, line);
    if (parts.length == 2) e.rawRequest = req;
    if (!targetOnly.isEmpty()) e.sourceRequest = "";
    e.timezoneUnknown = true;
    e.wallTime = wall;
    e.logType = "http_error-log";
    String message = body.split(", client: ", 2)[0];
    e.authFailure =
        subType.equals("auth_fail") || nginx && match("nginxAuthFailure", message) != null;
    if (e.authFailure) subType = "auth_fail";
    if (body.contains("[core:") && body.contains("Invalid URI")) subType = "invalid_uri";
    if (nginx && message.contains("limiting requests, excess")) subType = "req_limit_exceeded";
    if (body.contains("[ssl:") && body.contains("SSL handshake stopped"))
      subType = "ssl_handshake_stopped";
    e.subType = subType;
    m = match("errorHost", body);
    if (m != null && !m.group(1).isEmpty()) e.host = m.group(1);
    return e;
  }
}
