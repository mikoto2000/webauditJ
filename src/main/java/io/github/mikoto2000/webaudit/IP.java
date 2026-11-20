package io.github.mikoto2000.webaudit;

import java.net.*;

final class IP {
  private IP() {}

  static InetAddress parse(String s) {
    if (s == null || s.isEmpty() || s.startsWith("[") || s.endsWith("]"))
      throw new IllegalArgumentException("invalid IP");
    String literal = s;
    int zone = literal.indexOf('%');
    if (zone >= 0) {
      if (!literal.contains(":") || zone == literal.length() - 1)
        throw new IllegalArgumentException("invalid zone");
      literal = literal.substring(0, zone);
    }
    if (!literal.contains(":")) {
      String[] parts = literal.split("\\.", -1);
      if (parts.length != 4) throw new IllegalArgumentException("invalid IPv4");
      for (String p : parts)
        if (p.isEmpty()
            || p.length() > 3
            || p.length() > 1 && p.charAt(0) == '0'
            || !p.chars().allMatch(c -> c >= '0' && c <= '9')
            || Integer.parseInt(p) > 255) throw new IllegalArgumentException("invalid IPv4");
    }
    return InetAddress.ofLiteral(literal);
  }

  static String canonical(String s) {
    try {
      byte[] b = parse(s).getAddress();
      if (b.length == 4)
        return (b[0] & 255) + "." + (b[1] & 255) + "." + (b[2] & 255) + "." + (b[3] & 255);
      int best = -1, size = 1;
      for (int i = 0; i < 8; ) {
        if (b[i * 2] != 0 || b[i * 2 + 1] != 0) {
          i++;
          continue;
        }
        int j = i;
        while (j < 8 && b[j * 2] == 0 && b[j * 2 + 1] == 0) j++;
        if (j - i > size) {
          best = i;
          size = j - i;
        }
        i = j;
      }
      var out = new StringBuilder();
      for (int i = 0; i < 8; i++) {
        if (i == best) {
          out.append("::");
          i += size - 1;
          continue;
        }
        if (!out.isEmpty() && out.charAt(out.length() - 1) != ':') out.append(':');
        out.append(Integer.toHexString(((b[2 * i] & 255) << 8) | (b[2 * i + 1] & 255)));
      }
      return out.toString();
    } catch (IllegalArgumentException ex) {
      return s;
    }
  }
}
