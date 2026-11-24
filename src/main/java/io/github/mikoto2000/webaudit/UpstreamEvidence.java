package io.github.mikoto2000.webaudit;

import java.util.*;

/** Bounded source-log samples for the HTML report, captured during parsing. */
final class UpstreamEvidence {
  private final long limit;
  private long retained;

  UpstreamEvidence(long limit) {
    this.limit = limit;
  }

  void add(List<Map<String, Object>> samples, Event e) {
    if (samples.size() >= 8) return;
    String raw = Core.clip(e.raw, 4096);
    long bytes = Core.size(raw) + Core.size(e.file) + 64L;
    if (bytes > limit - retained) return;
    retained += bytes;
    var sample = Json.map("file", e.file, "line", e.line, "raw", raw);
    if (e.evidenceTruncated || !raw.equals(e.raw)) sample.put("evidence_truncated", true);
    samples.add(sample);
  }

  void attach(Map<String, Object> alert, List<Map<String, Object>> samples) {
    alert.put("evidence", Core.nullable(new ArrayList<>(samples)));
    if (Json.number(alert.get("count")) > samples.size()) alert.put("evidence_truncated", true);
  }
}
