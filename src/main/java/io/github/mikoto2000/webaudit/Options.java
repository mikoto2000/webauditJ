package io.github.mikoto2000.webaudit;

import java.time.Clock;

public final class Options {
  public int maxLineBytes = 65536, maxKeys = 4096, maxFindings = 2000, maxEvidenceBytes = 33554432;
  public long maxFileBytes = 8589934592L;
  public boolean deduplicateFiles;
  public boolean retainUpstreamEvidence;
  public String logRegex = "", errorTimezone = "";
  public Clock clock = Clock.systemUTC();
  public GeoIP geoIP;
  BundleCapture bundle;
}
