package io.github.mikoto2000.webaudit;

import java.time.OffsetDateTime;
import java.util.Map;

public final class Event implements Cloneable {
  String format = "unknown";
  public String ip = "", target = "", path = "", file = "", logType = "http_access-log";
  public String recordedUA,
      recordedReferer,
      sourceRequest,
      subType,
      rawRequest,
      wallTime,
      envelope,
      suffix;
  public String host, method, query, protocol, ua, referer, raw = "";
  public boolean malformed, authFailure, timezoneUnknown, evidenceTruncated;
  public OffsetDateTime time;
  public Integer status;
  public Long bytes;
  public long line;

  Event copy() {
    try {
      return (Event) clone();
    } catch (CloneNotSupportedException e) {
      throw new AssertionError(e);
    }
  }

  public Map<String, Object> toMap() {
    var m =
        Json.map(
            "raw_request",
            rawRequest,
            "log_type",
            logType,
            "time",
            timezoneUnknown ? null : Times.text(time),
            "ip",
            ip,
            "host",
            host,
            "method",
            method,
            "target",
            target,
            "path",
            path,
            "query",
            query,
            "protocol",
            protocol,
            "status",
            status,
            "bytes",
            bytes,
            "user_agent",
            ua,
            "referer",
            referer,
            "file",
            file,
            "line",
            line,
            "raw",
            raw);
    if (recordedUA != null) m.put("recorded_user_agent", recordedUA);
    if (recordedReferer != null) m.put("recorded_referer", recordedReferer);
    if (sourceRequest != null) m.put("source_request", sourceRequest);
    if (subType != null && !subType.isEmpty()) m.put("sub_type", subType);
    if (malformed) m.put("request_malformed", true);
    if (authFailure) m.put("auth_failure", true);
    if (timezoneUnknown) m.put("timezone_unknown", true);
    if (wallTime != null) m.put("wall_time", wallTime);
    if (envelope != null) m.put("syslog_envelope", envelope);
    if (suffix != null) m.put("unmapped_suffix", suffix);
    if (evidenceTruncated) m.put("evidence_truncated", true);
    return m;
  }
}
