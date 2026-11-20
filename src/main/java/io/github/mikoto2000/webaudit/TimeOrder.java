package io.github.mikoto2000.webaudit;

import java.time.OffsetDateTime;

final class TimeOrder {
  private OffsetDateTime instant, wall;
  private String file = "";
  boolean outOfOrder;

  void observe(Event e) {
    if (e.timezoneUnknown) {
      if (file.equals(e.file) && wall != null && e.time.isBefore(wall)) outOfOrder = true;
      file = e.file;
      wall = e.time;
    } else {
      if (instant != null && e.time.isBefore(instant)) outOfOrder = true;
      instant = e.time;
    }
  }
}
