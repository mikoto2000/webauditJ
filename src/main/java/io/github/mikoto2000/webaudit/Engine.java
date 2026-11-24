package io.github.mikoto2000.webaudit;

import static io.github.mikoto2000.webaudit.Core.*;

import java.nio.file.Path;
import java.util.*;

public final class Engine {
  public static final String VERSION = "2.0.0", RULES_VERSION = "2026.11.20.2";

  private Engine() {}

  @SuppressWarnings("unchecked")
  static void warn(Map<String, Object> report, String text) {
    var warnings = (List<String>) report.get("warnings");
    if (warnings.size() < 50 && !warnings.contains(text)) warnings.add(text);
  }

  public static Map<String, Object> analyze(List<Path> paths, Options o) {
    var report =
        Json.map(
            "schema",
            "webaudit/2",
            "version",
            VERSION,
            "rules_version",
            RULES_VERSION,
            "analyzed_at",
            Times.instant(o.clock.instant()),
            "warnings",
            new ArrayList<String>(),
            "partial",
            false);
    var behavior = new Behavior(o);
    var evidence = o.retainUpstreamEvidence ? new UpstreamEvidence(o.maxEvidenceBytes) : null;
    var upstream = new Upstream(o, evidence);
    var aura = new AuraAnalysis(o, evidence);
    var correlator = new Correlator(o);
    var geo = o.geoIP == null ? null : new GeoAnalysis(o.geoIP, o.maxKeys);
    var order = new TimeOrder();
    new LogInput(
            o,
            report,
            e -> {
              if (geo != null) geo.observe(e.ip);
              order.observe(e);
              if (o.bundle != null && o.bundle.requests != null) o.bundle.requests.pending.clear();
              upstream.observe(e);
              aura.observe(e);
              var detection = Signatures.detect(e);
              if (o.bundle != null) o.bundle.coverage.observe(e, detection);
              correlator.add(e, detection);
              if (o.bundle != null && o.bundle.requests != null)
                o.bundle.requests.observe(e, detection, correlator);
              if (!e.timezoneUnknown) behavior.observe(e, detection.hits());
            })
        .stream(paths);
    var signals = behavior.finish();
    if (o.bundle != null) {
      o.bundle.coverage.signals = signals;
      o.bundle.coverage.ready = behavior.coverageReadiness();
    }
    for (var signal : signals) correlator.addSignal(signal);
    var findings = correlator.finish();
    if (o.bundle != null && o.bundle.requests != null) o.bundle.requests.correlator = correlator;
    report.put("findings", findings);
    report.put("upstream_alerts", nullable(upstream.alerts));
    report.put("aura_matches", nullable(upstream.auraMatches()));
    report.put("aura_analysis", nullable(aura.finish()));
    report.put("upstream_rules", SourceMatcher.RULES);
    var sources = new TreeMap<String, Object>();
    for (String key : List.of("hub", "crowdsec", "AuraDFIR", "sec-lists"))
      sources.put(key, SourceMatcher.SOURCES.get(key));
    report.put("upstream_sources", sources);
    for (String w : aura.warnings) {
      warn(report, w);
      report.put("partial", true);
    }
    for (String w : upstream.warnings) {
      warn(report, w);
      report.put("partial", true);
    }
    var outcomes =
        Json.map(
            "confirmed_success",
            0,
            "possible_success",
            0,
            "unknown",
            0,
            "likely_failed",
            0,
            "confirmed_failure",
            0);
    var categories = new TreeMap<String, Long>();
    var severities = new TreeMap<String, Long>();
    for (var f : findings) {
      String verdict = Json.string(Json.obj(f.get("outcome")).get("verdict"));
      outcomes.put(verdict, Json.number(outcomes.get(verdict)) + 1);
      severities.merge(Json.string(f.get("severity")), 1L, Long::sum);
      for (Object cat : (List<?>) f.get("categories"))
        categories.merge((String) cat, 1L, Long::sum);
    }
    report.put("outcomes", outcomes);
    report.put("categories", categories);
    report.put("severities", severities);
    for (var collection : List.of(behavior.warnings, correlator.warnings))
      for (String w : collection) {
        warn(report, w);
        if (w.contains("limit reached")) report.put("partial", true);
      }
    if (order.outOfOrder) {
      report.put("partial", true);
      warn(
          report,
          "Input time order is incomplete; upstream stateful parity requires chronological input;"
              + " WebAudit correlations use fixed event-time partitions");
    }
    Json.obj(report.get("missing_fields"))
        .forEach((field, count) -> {
          if (Json.number(count) > 0)
            warn(
                report,
                "Missing "
                    + field
                    + " in "
                    + count
                    + " parsed requests reduces related detection coverage");
        });
    if (geo != null) geo.finish(report);
    return report;
  }
}
