package io.github.mikoto2000.webaudit;

import java.util.Map;
import java.time.OffsetDateTime;

record Signal(Map<String,Object> rule, Event event, long count, String reason, OffsetDateTime start, OffsetDateTime end) {}
