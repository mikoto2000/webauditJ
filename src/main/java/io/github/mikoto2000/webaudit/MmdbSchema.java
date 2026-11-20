package io.github.mikoto2000.webaudit;

final class MmdbSchema {
  private MmdbSchema() {}

  static boolean validAsn(Object value) {
    if (value instanceof java.math.BigInteger n) return n.signum() >= 0 && n.bitLength() <= 32;
    return (value instanceof Byte
            || value instanceof Short
            || value instanceof Integer
            || value instanceof Long)
        && ((Number) value).longValue() >= 0
        && ((Number) value).longValue() <= 0xffffffffL;
  }
}
