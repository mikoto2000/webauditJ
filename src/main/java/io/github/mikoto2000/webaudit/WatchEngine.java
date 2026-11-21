package io.github.mikoto2000.webaudit;

import java.time.*;
import java.util.*;
import java.util.function.Consumer;

/** Bounded, event-time re-evaluation using the batch native detectors. */
final class WatchEngine {
  record Record(Event event, List<String> rules, Instant received) {}

  final List<Record> records = new ArrayList<>();
  final Map<String, Map<String, Object>> incidents = new TreeMap<>();
  final WatchCommand.Arguments options;
  final Consumer<String> warn;
  final GeoIP geo;
  final Map<String, Map<String, Object>> rules = new HashMap<>();
  Instant maxTime = Instant.MIN, finalized = Instant.MIN;
  long sequence;
  boolean dirty;
  final Set<String> notifications = new HashSet<>();

  WatchEngine(WatchCommand.Arguments options, GeoIP geo, Consumer<String> warn) {
    this.options = options;
    this.geo = geo;
    this.warn = warn;
    for (var r : Json.rows(Json.resource("rules.json"))) rules.put(Json.string(r.get("id")), r);
  }

  static String hash(String s) {
    return HexFormat.of().formatHex(Core.sha(s.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
  }

  static Event sanitize(Event v) {
    Event e = new Event();
    e.time = v.time;
    e.ip = v.ip;
    e.file = v.file;
    e.line = v.line;
    e.status = v.status;
    e.bytes = v.bytes;
    e.malformed = v.malformed;
    e.path = hash(v.path);
    String p = v.path.toLowerCase(Locale.ROOT);
    if (p.equals("/signin") || p.endsWith("/login") || p.endsWith("/wp-login.php"))
      e.path = "/" + e.path + "/login";
    e.host = v.host == null ? null : hash(v.host);
    e.ua = v.ua == null ? null : hash(v.ua);
    e.method = v.method;
    if (e.method != null
        && !Set.of("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE")
            .contains(e.method)) e.method = hash(e.method);
    return e;
  }

  boolean observe(Event e, Instant received) {
    if (e.time == null || e.timezoneUnknown || !"http_access-log".equals(e.logType)) {
      warn.accept("watch accepts timestamped access logs only");
      return false;
    }
    Instant t = e.time.toInstant();
    if (t.isAfter(received.plusSeconds(300))) {
      warn.accept("event more than five minutes in future discarded");
      return false;
    }
    if (t.isBefore(finalized)) {
      warn.accept("event in finalized partition discarded");
      return false;
    }
    if (!maxTime.equals(Instant.MIN) && t.isBefore(maxTime.minus(options.lateness()))) {
      warn.accept("late event older than watermark discarded");
      return false;
    }
    if (t.isAfter(maxTime)) maxTime = t;
    var hits = Signatures.detect(e).hits().stream().map(r -> Json.string(r.get("id"))).toList();
    if (records.size() >= options.maxEvents) {
      records.removeFirst();
      warn.accept("event retention count limit reached; detection coverage reduced");
    }
    records.add(new Record(sanitize(e), hits, received));
    dirty = true;
    return true;
  }

  void stamp(Map<String, Object> v, String kind, Instant now) {
    v.put("schema_version", 1);
    v.put("event_type", kind);
    v.put("sequence", ++sequence);
    v.put("updated_at", now.toString());
    v.put(
        "event_id",
        "evt-"
            + hash(v.get("incident_id") + "/" + v.get("revision") + "/" + kind).substring(0, 32));
  }

  List<Map<String, Object>> flush(Instant now) {
    notifications.clear();
    var out = new ArrayList<Map<String, Object>>();
    if (dirty) {
      var o = new Options();
      o.maxFindings = 2000;
      o.maxEvidenceBytes = 2 << 20;
      var b = new Behavior(o);
      var c = new Correlator(o);
      records.stream()
          .sorted(Comparator.comparing(r -> r.event.time.toInstant()))
          .forEach(r -> {
            var hits = r.rules.stream().map(rules::get).filter(Objects::nonNull).toList();
            b.observe(r.event, hits);
            c.add(r.event, new Signatures.Detection(hits, Normalizer.normalize("")));
          });
      for (var s : b.finish()) c.addSignal(s);
      for (var w : b.warnings) if (w.toLowerCase(Locale.ROOT).contains("limit")) warn.accept(w);
      var findings =
          c.finish().stream().sorted(Comparator.comparing(f -> Json.string(f.get("id")))).toList();
      for (var w : c.warnings) warn.accept(w);
      for (var f : findings) {
        String id = Json.string(f.get("id"));
        var evidence = new ArrayList<Map<String, Object>>();
        for (var sample : Json.rows(f.get("evidence"))) {
          var e = Json.obj(sample.get("event"));
          evidence.add(Json.map("file", e.get("file"), "line", e.get("line")));
        }
        var outcome = Json.obj(f.get("outcome"));
        var v =
            Json.map(
                "incident_id",
                id,
                "first_event_at",
                f.get("first"),
                "last_event_at",
                f.get("last"),
                "severity",
                f.get("severity"),
                "category",
                String.join(
                    ",", ((List<?>) f.get("categories")).stream().map(Object::toString).toList()),
                "outcome",
                outcome.get("verdict"),
                "confidence",
                outcome.get("confidence"),
                "source_ips",
                List.of(f.get("ip")),
                "evidence",
                evidence,
                "rule_ids",
                Json.rows(f.get("rules")).stream().map(r -> r.get("id")).toList(),
                "count",
                f.get("count"));
        String fingerprint = hash(Json.string(v));
        var prev = incidents.get(id);
        if (prev != null
            && (Json.bool(prev.get("closed")) || fingerprint.equals(prev.get("fingerprint"))))
          continue;
        if (prev == null && incidents.size() >= 2000) {
          warn.accept("incident retention limit reached");
          continue;
        }
        var old = prev == null ? null : Json.obj(prev.get("event"));
        v.put("revision", old == null ? 1L : Json.number(old.get("revision")) + 1);
        v.put("created_at", old == null ? now.toString() : old.get("created_at"));
        boolean notify =
            old == null
                || Core.weight(Json.string(v.get("severity")))
                    > Core.weight(Json.string(old.get("severity")))
                || !v.get("outcome").equals(old.get("outcome"));
        if (geo != null) v.put("geoip", geo.lookup(Json.string(f.get("ip"))));
        stamp(v, old == null ? "incident_created" : "incident_updated", now);
        if (notify) notifications.add(Json.string(v.get("event_id")));
        incidents.put(
            id,
            Json.map("event", v, "fingerprint", fingerprint, "closed", false, "notify", notify));
        out.add(v);
      }
      dirty = false;
    }
    for (var s : incidents.values()) {
      var v = Json.obj(s.get("event"));
      Instant end =
          Instant.ofEpochSecond(
              Math.floorDiv(
                          Instant.parse(Json.string(v.get("last_event_at"))).getEpochSecond(), 300)
                      * 300
                  + 300);
      Instant updated = Instant.parse(Json.string(v.get("updated_at")));
      if (!Json.bool(s.get("closed"))
          && (maxTime.isAfter(end.plus(options.lateness()))
              || now.isAfter(updated.plusSeconds(300).plus(options.lateness())))) {
        if (end.isAfter(finalized)) finalized = end;
        v = new LinkedHashMap<>(v);
        v.put("revision", Json.number(v.get("revision")) + 1);
        stamp(v, "incident_closed", now);
        s.put("event", v);
        s.put("closed", true);
        s.put("notify", false);
        out.add(v);
      }
    }
    incidents
        .values()
        .removeIf(s ->
            Json.bool(s.get("closed"))
                && now.isAfter(
                    Instant.parse(Json.string(Json.obj(s.get("event")).get("updated_at")))
                        .plus(options.retention())));
    if (!maxTime.equals(Instant.MIN)) {
      boolean removed =
          records.removeIf(r ->
              r.event.time.toInstant().isBefore(maxTime.minus(options.retention()))
                  || now.isAfter(r.received.plus(options.retention())));
      dirty |= removed;
    }
    return out;
  }

  Map<String, Object> snapshot() {
    var saved =
        records.stream()
            .map(r ->
                Json.map(
                    "event", r.event.toMap(), "rules", r.rules, "received", r.received.toString()))
            .toList();
    return Json.map(
        "records",
        saved,
        "incidents",
        incidents,
        "max_time",
        maxTime.toString(),
        "finalized",
        finalized.toString(),
        "sequence",
        sequence);
  }

  void restore(Map<String, Object> data) {
    dirty = true;
    var saved = Json.rows(data.get("records"));
    var states = Json.obj(data.get("incidents"));
    if (saved.size() > options.maxEvents || states.size() > 2000)
      throw new IllegalArgumentException("state collections exceed limits");
    maxTime = Instant.parse(Json.string(data.get("max_time")));
    finalized = Instant.parse(Json.string(data.get("finalized")));
    sequence = Json.number(data.get("sequence"));
    if (sequence < 0) throw new IllegalArgumentException("invalid sequence");
    for (var r : saved) {
      var m = Json.obj(r.get("event"));
      Event e = new Event();
      e.ip = Json.string(m.get("ip"));
      e.file = Json.string(m.get("file"));
      e.line = Json.number(m.get("line"));
      e.time = OffsetDateTime.parse(Json.string(m.get("time")));
      e.path = Json.string(m.get("path"));
      e.host = (String) m.get("host");
      e.ua = (String) m.get("user_agent");
      e.method = (String) m.get("method");
      e.status = m.get("status") == null ? null : ((Number) m.get("status")).intValue();
      e.bytes = m.get("bytes") == null ? null : Json.number(m.get("bytes"));
      e.malformed = Json.bool(m.get("request_malformed"));
      var ids = ((List<?>) r.get("rules")).stream().map(Object::toString).toList();
      if (ids.stream().anyMatch(id -> !rules.containsKey(id)))
        throw new IllegalArgumentException("unknown saved rule");
      records.add(new Record(e, ids, Instant.parse(Json.string(r.get("received")))));
    }
    for (var entry : states.entrySet()) {
      var s = Json.obj(entry.getValue());
      var e = Json.obj(s.get("event"));
      if (!entry.getKey().equals(e.get("incident_id"))
          || Json.number(e.get("revision")) < 1
          || Json.number(e.get("sequence")) > sequence
          || Json.number(e.get("schema_version")) != 1)
        throw new IllegalArgumentException("invalid incident state");
      Instant.parse(Json.string(e.get("updated_at")));
      Instant.parse(Json.string(e.get("last_event_at")));
      incidents.put(entry.getKey(), s);
    }
  }
}
