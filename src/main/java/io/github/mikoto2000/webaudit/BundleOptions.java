package io.github.mikoto2000.webaudit;

import java.util.*;

/** Explicit investigator metadata. Values unavailable from logs remain unspecified. */
public final class BundleOptions {
  public String title = "",
      system = "",
      background = "",
      purpose = "",
      investigator = "",
      language = "ja";
  public long maxSpoolBytes = 1L << 30, maxOutputBytes = 1L << 30;
  public boolean includeSensitiveEvidence;
  public final List<String> warnings = new ArrayList<>();

  Map<String, Object> map() {
    return Json.map(
        "title",
        title,
        "system",
        system,
        "background",
        background,
        "purpose",
        purpose,
        "investigator",
        investigator,
        "language",
        language,
        "max_spool_bytes",
        maxSpoolBytes,
        "max_output_bytes",
        maxOutputBytes,
        "include_sensitive_evidence",
        includeSensitiveEvidence);
  }
}
