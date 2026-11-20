package io.github.mikoto2000.webaudit;

import java.time.OffsetDateTime;
import java.util.Map;

public final class Event {
    public String ip="", target="", path="", file="", logType="http_access-log";
    public String recordedUA, recordedReferer, sourceRequest, subType, rawRequest, wallTime, envelope, suffix;
    public String host, method, query, protocol, ua, referer, raw="";
    public boolean malformed, authFailure, timezoneUnknown, evidenceTruncated;
    public OffsetDateTime time;
    public Integer status;
    public Long bytes;
    public long line;
    public Map<String,Object> toMap() { return Map.of(); }
}
