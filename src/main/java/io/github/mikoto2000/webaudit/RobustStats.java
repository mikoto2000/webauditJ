package io.github.mikoto2000.webaudit;

import java.util.List;

final class RobustStats {
  private RobustStats() {}

  private static double median(List<Double> v) {
    if (v.isEmpty()) return 0;
    double[] a = v.stream().mapToDouble(Double::doubleValue).sorted().toArray();
    int i = a.length / 2;
    return a.length % 2 == 0 ? (a[i - 1] + a[i]) / 2 : a[i];
  }

  static boolean outlier(double value, List<Double> base, double floor, double ratio) {
    if (base.size() < 20) return false;
    double m = median(base), mad = median(base.stream().map(v -> Math.abs(v - m)).toList());
    return value > m + Math.max(floor, 6 * 1.4826 * mad) && value > m * ratio;
  }
}
