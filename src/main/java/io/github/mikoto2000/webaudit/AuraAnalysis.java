package io.github.mikoto2000.webaudit;

import static io.github.mikoto2000.webaudit.Core.*;

import java.time.*;
import java.util.*;

final class AuraAnalysis {
  final List<String> warnings = new ArrayList<>();
  private final Options o;

  private static class Peer {
    long count, auth, notFound, worst;
    double bytes;
    OffsetDateTime first, last, notFoundFirst, notFoundLast;
  }

  private static class UA {
    String value;
    long count;

    UA(String value) {
      this.value = value;
    }
  }

  private final Map<String, Peer> peers = new HashMap<>();
  private final Map<String, Long> windows = new HashMap<>();
  private final Map<String, UA> uas = new HashMap<>();
  private final Map<Long, Long> hours = new TreeMap<>();

  AuraAnalysis(Options o) {
    this.o = o;
  }

  void observe(Event e) {
    if (e.timezoneUnknown || !e.logType.equals("http_access-log")) return;
    if (peers.size() + windows.size() + uas.size() + hours.size() >= o.maxKeys) {
      unique(warnings, "Aura aggregation limit reached; source aggregations are incomplete");
      return;
    }
    Peer p = peers.computeIfAbsent(e.ip, _ -> new Peer());
    p.count++;
    p.bytes += e.bytes == null ? 0 : e.bytes;
    if (p.first == null || e.time.isBefore(p.first)) p.first = e.time;
    if (p.last == null || e.time.isAfter(p.last)) p.last = e.time;
    if (e.status != null && e.status == 404) {
      if (p.notFound == 0 || e.time.isBefore(p.notFoundFirst)) p.notFoundFirst = e.time;
      if (p.notFound == 0 || e.time.isAfter(p.notFoundLast)) p.notFoundLast = e.time;
      p.notFound++;
    }
    if (e.status != null && (e.status == 401 || e.status == 403)) {
      p.auth++;
      String key = e.ip + "/" + (Math.floorDiv(e.time.toEpochSecond(), 300) * 300);
      long n = windows.merge(key, 1L, Long::sum);
      p.worst = Math.max(p.worst, n);
    }
    String ua = SourceMatcher.sourceUA(e), key = digest(ua);
    UA u = uas.get(key);
    if (u == null) {
      String value = clip(ua, 512);
      if (!value.equals(ua))
        unique(
            warnings, "Aura User-Agent samples truncated; source references remain authoritative");
      u = new UA(value);
      uas.put(key, u);
    }
    u.count++;
    hours.merge(Math.floorDiv(e.time.toEpochSecond(), 3600) * 3600, 1L, Long::sum);
  }

  private List<String> top(java.util.function.ToLongFunction<Peer> count, int max) {
    return peers.keySet().stream()
        .sorted((a, b) -> {
          int c = Long.compare(count.applyAsLong(peers.get(b)), count.applyAsLong(peers.get(a)));
          return c != 0 ? c : a.compareTo(b);
        })
        .limit(max)
        .toList();
  }

  private static Map<String, Object> alert(
      String rule, String ip, String group, long count, OffsetDateTime first, OffsetDateTime last) {
    return Json.map(
        "source",
        "AuraDFIR/analysis",
        "rule_id",
        rule,
        "ip",
        ip,
        "group",
        group,
        "count",
        count,
        "first",
        Times.text(first),
        "last",
        Times.text(last),
        "events",
        null);
  }

  List<Map<String, Object>> finish() {
    var out = new ArrayList<Map<String, Object>>();
    for (String ip : top(p -> p.auth, 200)) {
      Peer p = peers.get(ip);
      if (p.worst >= 20) out.add(alert("brute_force", ip, ip, p.auth, null, null));
    }
    for (String ip : top(p -> p.notFound, 200)) {
      Peer p = peers.get(ip);
      if (p.notFound >= 50)
        out.add(alert("enumeration_404", ip, ip, p.notFound, p.notFoundFirst, p.notFoundLast));
    }
    var totals = top(p -> p.count, 500);
    if (totals.size() >= 5) {
      double mean = totals.stream().mapToDouble(ip -> peers.get(ip).bytes).average().orElse(0),
          variance =
              totals.stream().mapToDouble(ip -> Math.pow(peers.get(ip).bytes - mean, 2)).sum()
                  / totals.size(),
          sd = Math.sqrt(variance);
      for (String ip : totals) {
        Peer p = peers.get(ip);
        if (sd > 0 && p.bytes > 10 * 1024 * 1024 && p.bytes > mean + 3 * sd)
          out.add(alert("exfil_bytes", ip, ip, p.count, null, null));
      }
    }
    appendRareUserAgents(out);
    if (!hours.isEmpty()) {
      long lo = Collections.min(hours.keySet()), hi = Collections.max(hours.keySet());
      double n = (hi - lo) / 3600 + 1;
      if (n >= 6) {
        double sum = 0, squares = 0;
        for (long v : hours.values()) {
          sum += v;
          squares += (double) v * v;
        }
        double mean = sum / n, sd = Math.sqrt(Math.max(0, squares / n - mean * mean));
        if (sd > 0)
          for (var entry : hours.entrySet())
            if ((entry.getValue() - mean) / sd > 3) {
              var t = Instant.ofEpochSecond(entry.getKey()).atOffset(ZoneOffset.UTC);
              out.add(alert("traffic_spike", "", Times.text(t), entry.getValue(), t, null));
            }
      }
    }
    if (out.size() > o.maxFindings) {
      unique(warnings, "Aura finding limit reached; source aggregations are incomplete");
      return List.copyOf(out.subList(0, o.maxFindings));
    }
    return out;
  }

  private void appendRareUserAgents(List<Map<String, Object>> out) {
    var sorted =
        uas.values().stream()
            .sorted(Comparator.comparingLong((UA u) -> u.count).thenComparing(u -> u.value))
            .limit(25)
            .toList();
    for (UA u : sorted)
      if (u.count <= 5 && !u.value.isEmpty() && !u.value.equals("-"))
        out.add(alert("rare_user_agent", "", u.value, u.count, null, null));
  }
}
