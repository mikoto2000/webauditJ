package io.github.mikoto2000.webaudit;

import java.util.*;

final class Outcomes {
  private Outcomes() {}

  static Map<String, Object> infer(Correlator.Incident f) {
    var reasons =
        new ArrayList<>(
            List.of(
                "Access logs show requests and response metadata, not server-side execution or"
                    + " returned content"));
    var missing =
        new ArrayList<>(
            List.of(
                "Response content and expected resource semantics",
                "Request body, application/authentication audit trail",
                "Backend/proxy status mapping and filesystem/process/network evidence"));
    var next =
        new ArrayList<>(
            List.of(
                "Inspect the referenced original logs and confirm request routing and proxy"
                    + " configuration",
                "Correlate application/authentication and error logs for the same time and"
                    + " resource",
                "For payload probes inspect server files, processes and outbound connections"));
    String verdict = "unknown";
    double confidence = 0.2;
    if (f.sample.timezoneUnknown) missing.add("Verified timezone and cross-log time alignment");
    else {
      boolean possible =
          f.resources.values().stream()
              .anyMatch(r ->
                  r.blocked != null
                      && r.good.stream().filter(t -> t.isAfter(r.blocked)).count() >= 2);
      if (possible) {
        verdict = "possible_success";
        confidence = 0.55;
        reasons.add(
            "Same sensitive resource changed from blocked/not-found to repeated nonempty 2xx"
                + " responses; soft-404, redirects, generic pages or legitimate changes remain"
                + " possible");
        next.add(
            "Verify actual returned sensitive bytes against a nonexistent-path response; preserve"
                + " response/application evidence");
      } else if (f.blocked >= 3 && f.blocked == f.count) {
        verdict = "likely_failed";
        confidence = 0.5;
        reasons.add(
            "All observed responses in this activity were blocked/not-found, with at least three"
                + " observations; status mapping and unobserved attempts prevent confirmation");
      }
    }
    return Json.map(
        "verdict",
        verdict,
        "confidence",
        confidence,
        "reasons",
        reasons,
        "missing",
        missing,
        "next",
        next);
  }
}
