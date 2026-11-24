package io.github.mikoto2000.webaudit;

import static io.github.mikoto2000.webaudit.Core.*;

import java.io.*;
import java.time.*;
import java.util.*;

/** Full evidence association reuses actual native and source-engine membership. */
final class BundleRequests {
  final BundleCapture capture;
  final RequestSpool spool;
  final List<String> pending = new ArrayList<>();
  final IdentityHashMap<Map<String, Object>, String> sourceKeys = new IdentityHashMap<>();
  Correlator correlator;

  BundleRequests(BundleCapture capture, RequestSpool spool) {
    this.capture = capture;
    this.spool = spool;
  }

  String requestID(Event e) {
    return Bundle.id("REQ-", capture.inputs.get(e.file).get("id") + "\0" + e.line);
  }

  String bucketID(String key, Event e) {
    return Bundle.id("DET-", "hub\0" + key + "\0" + requestID(e));
  }

  void candidate(String id) {
    if (id != null && !pending.contains(id)) pending.add(id);
  }

  void observe(Event e, Signatures.Detection detection, Correlator correlator) {
    var hits = new ArrayList<Map<String, Object>>();
    for (var rule : detection.hits())
      hits.add(
          Json.map(
              "rule_id",
              rule.get("id"),
              "category",
              rule.get("category"),
              "severity",
              rule.get("severity"),
              "reason",
              rule.get("description"),
              "finding_id",
              correlator.findingID(e, rule)));
    var snapshot =
        Json.map(
            "request_id",
            requestID(e),
            "source_file_id",
            capture.inputs.get(e.file).get("id"),
            "event",
            e.toMap(),
            "_time",
            Times.text(e.time),
            "normalization",
            normalized(detection.normalization()),
            "hits",
            hits,
            "source_detections",
            List.copyOf(pending),
            "geoip",
            capture.options.geoIP == null ? null : capture.options.geoIP.lookup(e.ip));
    snapshot.put("request_duration", e.duration);
    snapshot.put("invalid_duration", e.invalidDuration);
    capture.statistics.observe(snapshot, e);
    spool.write(snapshot);
  }

  static List<Map<String, Object>> rows(Object value) {
    return BundleCoverage.rows(value);
  }

  static List<String> strings(Object value) {
    return value instanceof Collection<?> c ? c.stream().map(Object::toString).toList() : List.of();
  }

  static Event event(Map<String, Object> snapshot) {
    var v = Json.obj(snapshot.get("event"));
    var e = new Event();
    e.ip = Json.string(v.get("ip"));
    e.target = Json.string(v.get("target"));
    e.path = Json.string(v.get("path"));
    e.file = Json.string(v.get("file"));
    e.line = Json.number(v.get("line"));
    e.time = Times.parse((String) snapshot.get("_time"));
    e.timezoneUnknown = Json.bool(v.get("timezone_unknown"));
    e.wallTime = (String) v.get("wall_time");
    e.logType = Json.string(v.get("log_type"));
    e.host = (String) v.get("host");
    e.method = (String) v.get("method");
    e.protocol = (String) v.get("protocol");
    e.ua = (String) v.get("user_agent");
    e.recordedUA = (String) v.get("recorded_user_agent");
    e.referer = (String) v.get("referer");
    e.query = (String) v.get("query");
    e.raw = Json.string(v.get("raw"));
    e.status = v.get("status") == null ? null : (int) Json.number(v.get("status"));
    e.bytes = v.get("bytes") == null ? null : Json.number(v.get("bytes"));
    return e;
  }

  static final class Group {
    final Map<String, Object> row;
    final Signal signal;
    final Map<String, Object> source;
    final String matchKey;
    final ObservationMetrics metrics = new ObservationMetrics();

    Group(Map<String, Object> row, Signal signal, Map<String, Object> source, String matchKey) {
      this.row = row;
      this.signal = signal;
      this.source = source;
      this.matchKey = matchKey;
    }

    String id() {
      return (String) row.get("id");
    }

    String engine() {
      return (String) row.get("engine");
    }

    String rule() {
      return (String) row.get("rule_id");
    }

    boolean direct() {
      return "direct".equals(row.get("kind"));
    }

    boolean matches(Event e) {
      if (signal != null) {
        if (e.timezoneUnknown || e.time.isBefore(signal.start()) || e.time.isAfter(signal.end()))
          return false;
        if (rule().equals("WS-hour"))
          return e.time.toEpochSecond() / 3600 == signal.event().time.toEpochSecond() / 3600;
        return e.ip.equals(signal.event().ip) && s(e.host).equals(s(signal.event().host));
      }
      if (source == null || e.timezoneUnknown || !e.logType.equals("http_access-log")) return false;
      return switch (rule()) {
        case "brute_force" ->
            e.ip.equals(source.get("ip"))
                && (Objects.equals(e.status, 401) || Objects.equals(e.status, 403));
        case "enumeration_404" -> e.ip.equals(source.get("ip")) && Objects.equals(e.status, 404);
        case "exfil_bytes" -> e.ip.equals(source.get("ip"));
        case "rare_user_agent" -> digest(SourceMatcher.sourceUA(e)).equals(matchKey);
        case "traffic_spike" ->
            source.get("first") != null
                && Math.floorDiv(e.time.toEpochSecond(), 3600)
                    == Math.floorDiv(
                        Times.parse((String) source.get("first")).toEpochSecond(), 3600);
        default -> false;
      };
    }
  }

  List<Group> groups(Map<String, Object> report) {
    var result = new ArrayList<Group>();
    var rules = capture.coverage.rules;
    int i = 0;
    for (var signal : capture.coverage.signals) {
      String rule = (String) signal.rule().get("id");
      String id =
          Bundle.id(
              "DET-",
              "webaudit\0"
                  + rule
                  + "\0"
                  + (i++)
                  + "\0"
                  + Times.text(signal.start())
                  + "\0"
                  + Times.text(signal.end()));
      String fid = correlator.findingID(signal.event(), signal.rule());
      var row =
          baseDetection(
              id,
              "webaudit",
              rule,
              rule.equals("WS-size") || rule.equals("WS-url-size") ? "direct" : "related",
              signal.rule().get("category"),
              signal.rule().get("severity"),
              signal.reason(),
              Times.text(signal.start()),
              Times.text(signal.end()),
              signal.event().ip,
              signal.event().host,
              report);
      row.put("finding_ids", fid.isEmpty() ? List.of() : List.of(fid));
      result.add(new Group(row, signal, null, ""));
    }
    var analysis = Json.obj(report.get("analysis"));
    for (String engine : List.of("hub", "aura", "aura-analysis")) {
      String field =
          switch (engine) {
            case "hub" -> "upstream_alerts";
            case "aura" -> "aura_matches";
            default -> "aura_analysis";
          };
      var alerts = rows(analysis.get(field));
      for (int index = 0; index < alerts.size(); index++) {
        var a = alerts.get(index);
        String match = sourceKeys.getOrDefault(a, "");
        String id =
            a.get("id") instanceof String value
                ? value
                : Bundle.id(
                    "DET-",
                    Json.string(a.get("source"))
                        + "\0"
                        + a.get("rule_id")
                        + "\0"
                        + a.get("ip")
                        + "\0"
                        + a.get("group")
                        + "\0"
                        + Json.string(a.get("first"))
                        + "\0"
                        + match
                        + "\0"
                        + index);
        var row =
            baseDetection(
                id,
                engine,
                (String) a.get("rule_id"),
                engine.equals("aura-analysis") ? "related" : "direct",
                "",
                "unknown",
                Json.string(a.get("rule_id")),
                a.get("first"),
                a.get("last"),
                a.get("ip"),
                null,
                report);
        row.put("source_index", index);
        result.add(new Group(row, null, a, match));
      }
    }
    for (var group : result)
      for (var rule : rules)
        if (group.engine().equals(rule.get("engine")) && group.rule().equals(rule.get("id"))) {
          group.row.put("condition", rule.get("condition"));
          if (group.source != null) {
            group.row.put("category", rule.get("category"));
            group.row.put("reason", rule.get("description"));
            if (!Json.string(rule.get("severity")).isEmpty())
              group.row.put("severity", rule.get("severity"));
          }
          break;
        }
    return result;
  }

  static Map<String, Object> baseDetection(
      String id,
      String engine,
      String rule,
      String kind,
      Object category,
      Object severity,
      Object reason,
      Object first,
      Object last,
      Object ip,
      Object host,
      Map<String, Object> report) {
    return Json.map(
        "id",
        id,
        "engine",
        engine,
        "rule_id",
        rule,
        "kind",
        kind,
        "category",
        category,
        "severity",
        severity,
        "detection_confidence",
        "unknown",
        "reason",
        reason,
        "condition",
        "",
        "first",
        first,
        "last",
        last,
        "source_ip",
        ip,
        "host",
        host,
        "finding_ids",
        List.of(),
        "request_count",
        0L,
        "related_request_count",
        0L,
        "count_quality",
        report.get("count_quality"));
  }

  static final class Index {
    final Map<String, Group> tokens = new HashMap<>();
    final Map<String, List<Group>> windows = new HashMap<>(),
        scopes = new HashMap<>(),
        points = new HashMap<>(),
        ips = new HashMap<>(),
        uas = new HashMap<>();
    final Map<Long, List<Group>> hours = new HashMap<>(), nativeHours = new HashMap<>();

    static <K> void add(Map<K, List<Group>> map, K key, Group group) {
      map.computeIfAbsent(key, _ -> new ArrayList<>()).add(group);
    }

    static String scope(Event e) {
      return e.ip + "\0" + s(e.host);
    }

    Index(List<Group> groups) {
      for (var group : groups) {
        if (group.signal != null) {
          var signal = group.signal;
          if (group.direct()) add(points, signal.event().file + "\0" + signal.event().line, group);
          else if (group.rule().equals("WS-hour"))
            add(nativeHours, signal.event().time.toEpochSecond() / 3600, group);
          else if (group.rule().startsWith("WB-")
              && signal.end().toEpochSecond() - signal.start().toEpochSecond() <= 900) {
            long lo = Math.floorDiv(signal.start().toEpochSecond(), 300),
                hi = Math.floorDiv(signal.end().toEpochSecond(), 300);
            for (long bin = lo; bin <= hi; bin++)
              add(windows, scope(signal.event()) + "\0" + bin, group);
          } else add(scopes, scope(signal.event()), group);
        } else if (group.direct()) tokens.put(group.id(), group);
        else
          switch (group.rule()) {
            case "rare_user_agent" -> add(uas, group.matchKey, group);
            case "traffic_spike" -> {
              if (group.source.get("first") != null)
                add(
                    hours,
                    Math.floorDiv(
                        Times.parse((String) group.source.get("first")).toEpochSecond(), 3600),
                    group);
            }
            default -> add(ips, Json.string(group.source.get("ip")), group);
          }
      }
    }

    Set<Group> candidates(Map<String, Object> snapshot, Event e) {
      var out = new LinkedHashSet<Group>();
      for (String token : strings(snapshot.get("source_detections"))) {
        var group = tokens.get(token);
        if (group != null) out.add(group);
      }
      out.addAll(points.getOrDefault(e.file + "\0" + e.line, List.of()));
      if (!e.timezoneUnknown) {
        out.addAll(
            windows.getOrDefault(
                scope(e) + "\0" + Math.floorDiv(e.time.toEpochSecond(), 300), List.of()));
        out.addAll(scopes.getOrDefault(scope(e), List.of()));
        out.addAll(ips.getOrDefault(e.ip, List.of()));
        out.addAll(uas.getOrDefault(digest(SourceMatcher.sourceUA(e)), List.of()));
        out.addAll(hours.getOrDefault(Math.floorDiv(e.time.toEpochSecond(), 3600), List.of()));
        out.addAll(nativeHours.getOrDefault(e.time.toEpochSecond() / 3600, List.of()));
      }
      return out;
    }
  }

  record Association(Map<String, Object> row, Group group) {}

  record Matches(List<Association> direct, List<Association> related) {}

  static List<Map<String, Object>> direct(Map<String, Object> snapshot) {
    var result = new ArrayList<Map<String, Object>>();
    var e = event(snapshot);
    for (var hit : rows(snapshot.get("hits"))) {
      String rule = (String) hit.get("rule_id");
      var row =
          baseDetection(
              Bundle.id("DET-", "webaudit\0" + rule + "\0" + snapshot.get("request_id")),
              "webaudit",
              rule,
              "direct",
              hit.get("category"),
              hit.get("severity"),
              hit.get("reason"),
              e.timezoneUnknown ? null : Times.text(e.time),
              e.timezoneUnknown ? null : Times.text(e.time),
              e.ip,
              e.host,
              Json.map("count_quality", "exact"));
      String finding = Json.string(hit.get("finding_id"));
      row.put("finding_ids", finding.isEmpty() ? List.of() : List.of(finding));
      row.put("request_count", 1L);
      result.add(row);
    }
    return result;
  }

  static Matches match(Map<String, Object> snapshot, Event e, Index index) {
    var direct = new ArrayList<Association>();
    var related = new ArrayList<Association>();
    for (var row : direct(snapshot)) direct.add(new Association(row, null));
    for (var group : index.candidates(snapshot, e)) {
      boolean accepted = group.source != null && group.direct() || group.matches(e);
      if (!accepted) continue;
      (group.direct() ? direct : related).add(new Association(group.row, group));
    }
    return new Matches(direct, related);
  }

  static List<Association> all(Matches matches) {
    var result = new ArrayList<>(matches.direct);
    result.addAll(matches.related);
    return result;
  }

  static final List<String> REQUEST_HEADERS =
      List.of(
          "request_id",
          "finding_ids",
          "detection_ids",
          "timestamp",
          "source_ip",
          "country_code",
          "asn",
          "as_organization",
          "host",
          "method",
          "protocol",
          "request_uri",
          "normalized_uri",
          "status_code",
          "response_bytes",
          "request_duration",
          "referer",
          "user_agent",
          "attack_categories",
          "rule_ids",
          "detection_engines",
          "severity",
          "detection_confidence",
          "detection_reason",
          "source_file_id",
          "source_file",
          "source_line",
          "relation",
          "direct_detection_ids",
          "related_detection_ids",
          "normalization_steps",
          "raw_log",
          "count_quality");

  static String[] requestRow(
      Map<String, Object> snapshot, Event e, Matches matches, String quality) {
    var findings = new LinkedHashSet<String>();
    var ids = new LinkedHashSet<String>();
    var rules = new LinkedHashSet<String>();
    var categories = new LinkedHashSet<String>();
    var engines = new LinkedHashSet<String>();
    var reasons = new LinkedHashSet<String>();
    String severity = "unknown";
    for (var association : all(matches)) {
      var row = association.row;
      findings.addAll(strings(row.get("finding_ids")));
      ids.add((String) row.get("id"));
      rules.add((String) row.get("rule_id"));
      engines.add((String) row.get("engine"));
      if (!Json.string(row.get("category")).isEmpty()) categories.add((String) row.get("category"));
      reasons.add(Json.string(row.get("reason")));
      if (severity.equals("unknown") || weight(Json.string(row.get("severity"))) > weight(severity))
        severity = Json.string(row.get("severity"));
    }
    var normalization = Json.obj(snapshot.get("normalization"));
    var variants = strings(normalization.get("variants"));
    var geo =
        snapshot.get("geoip") == null ? Map.<String, Object>of() : Json.obj(snapshot.get("geoip"));
    String relation =
        matches.direct.isEmpty()
            ? "related"
            : matches.related.isEmpty() ? "direct" : "direct_and_related";
    return new String[] {
      Json.string(snapshot.get("request_id")),
      String.join(";", findings),
      String.join(";", ids),
      e.timezoneUnknown ? "" : Times.text(e.time),
      e.ip,
      Json.string(geo.get("country_code")),
      Json.string(geo.get("asn")),
      Json.string(geo.get("asn_organization")),
      s(e.host),
      s(e.method),
      s(e.protocol),
      e.target,
      variants.isEmpty() ? e.target : variants.getLast(),
      e.status == null ? "" : e.status.toString(),
      e.bytes == null ? "" : e.bytes.toString(),
      Json.string(snapshot.get("request_duration")),
      s(e.referer),
      s(e.ua),
      String.join(";", categories),
      String.join(";", rules),
      String.join(";", engines),
      severity,
      "unknown",
      String.join(";", reasons),
      Json.string(snapshot.get("source_file_id")),
      e.file,
      Long.toString(e.line),
      relation,
      Bundle.join(matches.direct.stream().map(a -> a.row.get("id")).toList()),
      Bundle.join(matches.related.stream().map(a -> a.row.get("id")).toList()),
      Bundle.join(normalization.get("steps")),
      e.raw,
      quality
    };
  }

  static final List<String> DETECTION_HEADERS =
      List.of(
          "detection_id",
          "engine",
          "rule_id",
          "relation",
          "category",
          "severity",
          "detection_confidence",
          "reason",
          "condition",
          "first",
          "last",
          "source_ip",
          "host",
          "finding_ids",
          "direct_request_count",
          "related_request_count",
          "count_quality");

  static void detectionRow(BundleWriter.Record write, Map<String, Object> row) throws IOException {
    write.accept(
        Bundle.cell(row, "id"),
        Bundle.cell(row, "engine"),
        Bundle.cell(row, "rule_id"),
        Bundle.cell(row, "kind"),
        Bundle.cell(row, "category"),
        Bundle.cell(row, "severity"),
        Bundle.cell(row, "detection_confidence"),
        Bundle.cell(row, "reason"),
        Bundle.cell(row, "condition"),
        Bundle.cell(row, "first"),
        Bundle.cell(row, "last"),
        Bundle.cell(row, "source_ip"),
        Bundle.cell(row, "host"),
        Bundle.join(row.get("finding_ids")),
        Bundle.cell(row, "request_count"),
        Bundle.cell(row, "related_request_count"),
        Bundle.cell(row, "count_quality"));
  }

  void export(BundleWriter writer, Map<String, Object> report) throws IOException {
    spool.finishWrite();
    boolean complete = Json.bool(report.get("complete")) && !spool.truncated;
    var reasons = new ArrayList<String>();
    if (!Json.bool(report.get("complete")))
      reasons.add("Analysis or original-file provenance is incomplete");
    if (spool.truncated)
      reasons.add("Private request spool byte limit reached; full request export is incomplete");
    if (capture.coverage.signals.stream().anyMatch(signal -> signal.event().evidenceTruncated)) {
      complete = false;
      reasons.add(
          "Delayed-detection source fields were compacted; complete association cannot be"
              + " guaranteed");
    }
    report.put("evidence_complete", complete);
    if (!complete) {
      report.put("complete", false);
      if (!report.get("status").equals("failed")) report.put("status", "partial");
      report.put("count_quality", "lower_bound");
      Json.obj(report.get("analysis")).put("partial", true);
      for (String reason : reasons) Engine.warn(Json.obj(report.get("analysis")), reason);
    }
    String quality = (String) report.get("count_quality");
    var groups = groups(report);
    var index = new Index(groups);
    var findings = new LinkedHashMap<String, ObservationMetrics>();
    for (var finding : rows(Json.obj(report.get("analysis")).get("findings")))
      findings.put((String) finding.get("id"), new ObservationMetrics());
    for (var group : groups)
      for (String fid : strings(group.row.get("finding_ids")))
        if (findings.containsKey(fid)) findings.get(fid).detections++;
    var counts = new HashMap<String, Long>();
    var relatedCounts = new HashMap<String, Long>();
    var aspectCounts = new HashMap<String, Long>();
    var relatedAspects = new HashMap<String, Long>();
    var aspectDetections = new HashMap<String, Long>();
    var aspectRules = new HashMap<String, List<String>>();
    for (var aspect : BundleCoverage.ASPECTS)
      for (String rule : strings(aspect.get("rules")))
        aspectRules
            .computeIfAbsent(BundleCoverage.key("webaudit", rule), _ -> new ArrayList<>())
            .add("ASPECT-" + aspect.get("id"));
    for (var group : groups)
      for (String aspect :
          aspectRules.getOrDefault(BundleCoverage.key(group.engine(), group.rule()), List.of()))
        aspectDetections.merge(aspect, 1L, Long::sum);
    long[] totals = new long[3];
    writer.csv(
        "suspicious-requests.csv",
        REQUEST_HEADERS,
        write ->
            spool.scan(snapshot -> {
              var e = event(snapshot);
              var matches = match(snapshot, e, index);
              if (!matches.direct.isEmpty()) {
                totals[0]++;
                capture.statistics.suspicious(snapshot, e);
                write.accept(requestRow(snapshot, e, matches, quality));
              }
              if (!matches.related.isEmpty()) totals[1]++;
              var seenDirect = new HashSet<String>();
              var seenRelated = new HashSet<String>();
              var seenAspects = new HashSet<String>();
              var seenRelatedAspects = new HashSet<String>();
              var seenFindings = new HashMap<String, Integer>();
              for (int flag : new int[] {1, 2})
                for (var association : flag == 1 ? matches.direct : matches.related) {
                  var row = association.row;
                  String key =
                      BundleCoverage.key((String) row.get("engine"), (String) row.get("rule_id"));
                  if (flag == 1) seenDirect.add(key);
                  else seenRelated.add(key);
                  if (association.group != null) {
                    association.group.metrics.observe(e, flag == 1, flag == 2);
                    String field = flag == 1 ? "request_count" : "related_request_count";
                    row.put(field, Json.number(row.get(field)) + 1);
                  } else if (flag == 1) totals[2]++;
                  for (String aspect : aspectRules.getOrDefault(key, List.of())) {
                    (flag == 1 ? seenAspects : seenRelatedAspects).add(aspect);
                    if (association.group == null && flag == 1)
                      aspectDetections.merge(aspect, 1L, Long::sum);
                  }
                  for (String fid : strings(row.get("finding_ids"))) {
                    seenFindings.merge(fid, flag, (a, b) -> a | b);
                    if (association.group == null && flag == 1 && findings.containsKey(fid))
                      findings.get(fid).detections++;
                  }
                }
              for (String key : seenDirect) counts.merge(key, 1L, Long::sum);
              for (String key : seenRelated) relatedCounts.merge(key, 1L, Long::sum);
              for (String key : seenAspects) aspectCounts.merge(key, 1L, Long::sum);
              for (String key : seenRelatedAspects) relatedAspects.merge(key, 1L, Long::sum);
              for (var entry : seenFindings.entrySet()) {
                var metrics = findings.get(entry.getKey());
                if (metrics != null)
                  metrics.observe(e, (entry.getValue() & 1) != 0, (entry.getValue() & 2) != 0);
              }
            }));
    writer.csv(
        "related-requests.csv",
        REQUEST_HEADERS,
        write ->
            spool.scan(snapshot -> {
              var e = event(snapshot);
              var matches = match(snapshot, e, index);
              if (!matches.related.isEmpty())
                write.accept(requestRow(snapshot, e, matches, quality));
            }));
    writer.csv(
        "detections.csv",
        DETECTION_HEADERS,
        write -> {
          spool.scan(snapshot -> {
            for (var row : direct(snapshot)) detectionRow(write, row);
          });
          for (var group : groups) detectionRow(write, group.row);
        });
    for (var group : groups) {
      var metrics = group.metrics.map("");
      group.row.put("status_counts", metrics.get("status_counts"));
      group.row.put("methods", metrics.get("methods"));
      group.row.put("uri_examples", metrics.get("uri_samples"));
      group.row.put("uri_statistics", metrics.get("uri_statistics"));
      group.row.put("retained_unique_uris", metrics.get("retained_unique_uris"));
      group.row.put("unique_uri_quality", metrics.get("unique_uri_quality"));
      group.row.put("metadata_truncated", metrics.get("uri_samples_truncated"));
      group.row.put("response_bytes", group.metrics.bytes());
      group.row.put("observed_first", metrics.get("first"));
      group.row.put("observed_last", metrics.get("last"));
    }
    report.put("detections", groups.stream().map(g -> g.row).toList());
    report.put(
        "finding_observations",
        findings.entrySet().stream().map(entry -> entry.getValue().map(entry.getKey())).toList());
    report.put(
        "evidence",
        Json.map(
            "suspicious_requests",
            totals[0],
            "related_requests",
            totals[1],
            "signature_detections",
            totals[2],
            "aggregate_detections",
            groups.size(),
            "spool_bytes",
            spool.used,
            "incomplete_reasons",
            reasons));
    for (var row : rows(report.get("coverage"))) {
      String id = (String) row.get("id");
      if (id.startsWith("RULE-")
          && strings(row.get("engines")).size() == 1
          && !strings(row.get("engines")).getFirst().equals("geoip")
          && !row.get("status").equals("unsupported")) {
        String key =
            BundleCoverage.key(
                strings(row.get("engines")).getFirst(), strings(row.get("rule_ids")).getFirst());
        row.put("detected_requests", counts.getOrDefault(key, 0L));
        row.put("related_requests", relatedCounts.getOrDefault(key, 0L));
        BundleCoverage.strings(row, "limitations")
            .removeIf(text ->
                text.startsWith(
                    "Distinct detected request count is unavailable until full evidence"
                        + " association"));
      } else if (id.startsWith("ASPECT-")
          && !id.equals("ASPECT-multi_ip")
          && !Set.of("unsupported", "unable", "not_performed").contains(row.get("status"))) {
        row.put("detected_requests", aspectCounts.getOrDefault(id, 0L));
        row.put("related_requests", relatedAspects.getOrDefault(id, 0L));
        row.put("detections", aspectDetections.getOrDefault(id, 0L));
      }
      if (!complete
          && !row.get("status").equals("unsupported")
          && !row.get("status").equals("not_performed")) {
        row.put("count_quality", "lower_bound");
        row.put("complete", false);
        if (Set.of("detected", "no_detection").contains(row.get("status"))) {
          row.put("status", "partial");
          row.put("evaluation", "partial");
        }
      }
    }
    writer.csv(
        "findings.csv",
        List.of(
            "finding_id",
            "source_ip",
            "host",
            "first",
            "last",
            "categories",
            "rule_ids",
            "direct_requests",
            "related_requests",
            "requests",
            "detections",
            "severity",
            "detection_confidence",
            "attack_score",
            "outcome",
            "outcome_confidence",
            "count_quality",
            "details_json"),
        write -> {
          for (var finding : rows(Json.obj(report.get("analysis")).get("findings"))) {
            var metrics = findings.get((String) finding.get("id"));
            var outcome = Json.obj(finding.get("outcome"));
            write.accept(
                Bundle.cell(finding, "id"),
                Bundle.cell(finding, "ip"),
                Bundle.cell(finding, "host"),
                Json.bool(finding.get("timezone_unknown")) ? "" : Bundle.cell(finding, "first"),
                Json.bool(finding.get("timezone_unknown")) ? "" : Bundle.cell(finding, "last"),
                Bundle.join(finding.get("categories")),
                Bundle.join(rows(finding.get("rules")).stream().map(r -> r.get("id")).toList()),
                Long.toString(metrics.direct),
                Long.toString(metrics.related),
                Long.toString(metrics.requests),
                Long.toString(metrics.detections),
                Bundle.cell(finding, "severity"),
                "unknown",
                Bundle.cell(finding, "attack_score"),
                Bundle.cell(outcome, "verdict"),
                Bundle.cell(outcome, "confidence"),
                quality,
                Json.MAPPER.writeValueAsString(
                    Json.map(
                        "incident",
                        finding,
                        "observations",
                        metrics.map((String) finding.get("id")))));
          }
        });
  }
}
