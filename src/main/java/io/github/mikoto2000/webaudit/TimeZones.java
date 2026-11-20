package io.github.mikoto2000.webaudit;

import java.time.DateTimeException;
import java.time.ZoneId;

final class TimeZones {
  private TimeZones() {}

  static ZoneId resolve(String name) {
    if (name.equals("Local")) return ZoneId.systemDefault();
    if (!ZoneId.getAvailableZoneIds().contains(name)) {
      throw new DateTimeException("unknown time zone " + name);
    }
    return ZoneId.of(name);
  }
}
