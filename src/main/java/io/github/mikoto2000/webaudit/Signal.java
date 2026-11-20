package io.github.mikoto2000.webaudit;

import java.time.OffsetDateTime;
import java.util.Map;

record Signal(
    Map<String, Object> rule,
    Event event,
    long count,
    String reason,
    OffsetDateTime start,
    OffsetDateTime end) {}
