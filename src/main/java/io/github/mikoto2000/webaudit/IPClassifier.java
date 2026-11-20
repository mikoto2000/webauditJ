package io.github.mikoto2000.webaudit;

import java.net.InetAddress;
import java.util.*;

final class IPClassifier {
  private IPClassifier() {}

  private record Prefix(byte[] bytes, int bits) {}

  private static final List<Prefix> RESERVED =
      prefixes(
          "0.0.0.0/8",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.88.99.0/24",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "240.0.0.0/4",
          "2001::/23",
          "2001:db8::/32",
          "2002::/16",
          "3fff::/20",
          "5f00::/16",
          "64:ff9b::/96",
          "64:ff9b:1::/48",
          "100::/64");

  private static List<Prefix> prefixes(String... cidrs) {
    return Arrays.stream(cidrs)
        .map(c -> {
          String[] p = c.split("/");
          return new Prefix(IP.parse(p[0]).getAddress(), Integer.parseInt(p[1]));
        })
        .toList();
  }

  private static boolean in(byte[] b, Prefix p) {
    if (b.length != p.bytes().length) return false;
    for (int i = 0; i < p.bits(); i++)
      if (((b[i / 8] ^ p.bytes()[i / 8]) & (0x80 >> (i % 8))) != 0) return false;
    return true;
  }

  private static boolean in(byte[] b, String cidr) {
    return in(b, prefixes(cidr).getFirst());
  }

  static String classify(String text) {
    if (text.contains("%")) return "invalid";
    InetAddress address;
    try {
      address = IP.parse(text);
    } catch (IllegalArgumentException e) {
      return "invalid";
    }
    byte[] b = address.getAddress();
    if (address.isAnyLocalAddress()) return "unspecified";
    if (address.isLoopbackAddress()) return "loopback";
    if (in(b, "10.0.0.0/8")
        || in(b, "172.16.0.0/12")
        || in(b, "192.168.0.0/16")
        || in(b, "fc00::/7")) return "private";
    if (address.isLinkLocalAddress()) return "link_local";
    if (address.isMulticastAddress()) return "multicast";
    if (in(b, "100.64.0.0/10")) return "shared";
    for (Prefix p : RESERVED) if (in(b, p)) return "reserved";
    if (b.length == 16 && !in(b, "2000::/3")) return "reserved";
    if (in(b, "255.255.255.255/32")) return "reserved";
    return "public";
  }
}
