package io.github.mikoto2000.webaudit;

import java.util.Map;

/** Missing, invalid and valid observations are disjoint; nonfinite sums stay unavailable. */
final class BundleNumeric {
  final String unit;
  long count, missing, invalid;
  Double sum, min, max, mean;
  String quality = "unavailable";

  BundleNumeric(String unit) {
    this.unit = unit;
  }

  void add(Double value, boolean bad) {
    if (bad) {
      invalid++;
      return;
    }
    if (value == null) {
      missing++;
      return;
    }
    if (!Double.isFinite(value) || value < 0) {
      invalid++;
      return;
    }
    count++;
    if (count == 1) {
      sum = value;
      quality = "finite";
    } else if (sum != null) {
      double next = sum + value;
      if (Double.isFinite(next)) sum = next;
      else {
        sum = null;
        quality = "overflow";
      }
    }
    if (min == null || value < min) min = value;
    if (max == null || value > max) max = value;
    mean = sum == null ? null : sum / count;
  }

  Map<String, Object> map() {
    return Json.map(
        "count",
        count,
        "missing",
        missing,
        "invalid",
        invalid,
        "sum",
        sum,
        "sum_quality",
        quality,
        "min",
        min,
        "max",
        max,
        "mean",
        mean,
        "unit",
        unit);
  }
}
