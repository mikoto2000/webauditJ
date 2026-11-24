package io.github.mikoto2000.webaudit;

import java.util.Arrays;
import java.util.List;

final class RobustStats {
  private RobustStats() {}

  private static double median(List<Double> v) {
    if (v.isEmpty()) return 0;
    double[] a = v.stream().mapToDouble(Double::doubleValue).sorted().toArray();
    int i = a.length / 2;
    return a.length % 2 == 0 ? (a[i - 1] + a[i]) / 2 : a[i];
  }

  static boolean outlier(
      double value, List<Double> base, double floor, double ratio, double[] scratch) {
    int count = base.size();
    if (count < 20) return false;
    if (count > scratch.length)
      throw new IllegalArgumentException("baseline exceeds scratch capacity");
    for (int i = 0; i < count; i++) scratch[i] = base.get(i);
    Arrays.sort(scratch, 0, count);
    double m = sortedMedian(scratch, count);
    for (int i = 0; i < count; i++) scratch[i] = Math.abs(base.get(i) - m);
    Arrays.sort(scratch, 0, count);
    double mad = sortedMedian(scratch, count);
    return value > m + Math.max(floor, 6 * 1.4826 * mad) && value > m * ratio;
  }

  private static double sortedMedian(double[] values, int count) {
    int i = count / 2;
    return count % 2 == 0 ? (values[i - 1] + values[i]) / 2 : values[i];
  }

  static boolean outlier(double value, List<Double> base, double floor, double ratio) {
    if (base.size() < 20) return false;
    double m = median(base), mad = median(base.stream().map(v -> Math.abs(v - m)).toList());
    return value > m + Math.max(floor, 6 * 1.4826 * mad) && value > m * ratio;
  }
}
