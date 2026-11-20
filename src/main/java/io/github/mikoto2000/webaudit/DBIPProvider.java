package io.github.mikoto2000.webaudit;

import com.google.re2j.Pattern;
import java.io.*;
import java.net.*;
import java.net.URI;
import java.net.http.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.YearMonth;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;

final class DBIPProvider implements GeoSource {
  record Response(int status, String location) {}

  interface Transport {
    Response get(URI uri, Duration timeout, OutputStream out, long limit) throws IOException;
  }

  private final Transport transport;
  static final Pattern DOWNLOAD_PATH =
      Pattern.compile("^/free/dbip-(country|asn)-lite-([0-9]{4}-(?:0[1-9]|1[0-2]))\\.mmdb\\.gz$");
  private static final Pattern DL = Pattern.compile("(?is)<dl\\b[^>]*>(.*?)</dl>"),
      FORMAT = Pattern.compile("(?is)<dt>\\s*Format\\s*</dt>\\s*<dd[^>]*>\\s*MMDB\\s*</dd>"),
      RELEASE = Pattern.compile("(?is)<dt>\\s*Release\\s*</dt>\\s*<dd[^>]*>\\s*([^<]+?)\\s*</dd>"),
      SHA =
          Pattern.compile("(?is)<dt>\\s*SHA1SUM\\s*</dt>\\s*<dd[^>]*>\\s*([a-f0-9]{40})\\s*</dd>"),
      HREF = Pattern.compile("(?is)\\bhref\\s*=\\s*[\"']([^\"']+)[\"']");

  DBIPProvider() {
    this.transport = new HttpTransport();
  }

  DBIPProvider(Transport transport) {
    this.transport = transport;
  }

  static void allowed(String raw) throws IOException {
    try {
      URI u = URI.create(raw);
      if (!"https".equals(u.getScheme())
          || u.getUserInfo() != null
          || u.getPort() != -1
          || u.getRawQuery() != null
          || u.getRawFragment() != null)
        throw new IOException("GeoIP requires official HTTPS URL: " + raw);
      if ("db-ip.com".equals(u.getRawAuthority())
          && (u.getPath().equals("/db/download/ip-to-country-lite")
              || u.getPath().equals("/db/download/ip-to-asn-lite"))) return;
      if ("download.db-ip.com".equals(u.getRawAuthority())
          && DOWNLOAD_PATH.matcher(u.getPath()).matches()) return;
    } catch (IllegalArgumentException ex) {
      throw new IOException("invalid GeoIP URL", ex);
    }
    throw new IOException("GeoIP URL is outside the official allowlist: " + raw);
  }

  private static String unescapeHtml(String s) {
    var p = Pattern.compile("&#(x[0-9a-fA-F]+|[0-9]+);").matcher(s);
    var out = new StringBuffer();
    while (p.find()) {
      String n = p.group(1);
      try {
        int cp =
            Integer.parseInt(n.startsWith("x") ? n.substring(1) : n, n.startsWith("x") ? 16 : 10);
        p.appendReplacement(
            out, java.util.regex.Matcher.quoteReplacement(new String(Character.toChars(cp))));
      } catch (IllegalArgumentException ex) {
        p.appendReplacement(out, java.util.regex.Matcher.quoteReplacement(p.group()));
      }
    }
    p.appendTail(out);
    return out.toString()
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
  }

  static Release parse(String html, String role) throws IOException {
    var blocks = new ArrayList<int[]>();
    var dl = DL.matcher(html);
    while (dl.find()) blocks.add(new int[] {dl.start(), dl.end(), dl.start(1), dl.end(1)});
    var found = new ArrayList<Release>();
    for (int i = 0; i < blocks.size(); i++) {
      int[] idx = blocks.get(i);
      String body = html.substring(idx[2], idx[3]);
      if (!FORMAT.matcher(body).find()) continue;
      var date = RELEASE.matcher(body);
      var sha = SHA.matcher(body);
      if (!date.find() || !sha.find()) continue;
      String month;
      try {
        month =
            YearMonth.parse(
                    date.group(1).strip(), DateTimeFormatter.ofPattern("MMMM uuuu", Locale.ENGLISH))
                .toString();
      } catch (java.time.DateTimeException ex) {
        continue;
      }
      var href =
          HREF.matcher(
              html.substring(idx[1], i + 1 < blocks.size() ? blocks.get(i + 1)[0] : html.length()));
      while (href.find()) {
        String raw = unescapeHtml(href.group(1));
        URI uri;
        try {
          uri = URI.create(raw);
        } catch (IllegalArgumentException ex) {
          continue;
        }
        var parts = DOWNLOAD_PATH.matcher(Core.s(uri.getPath()));
        if (!parts.matches() || !parts.group(1).equals(role)) continue;
        allowed(raw);
        if (!parts.group(2).equals(month))
          throw new IOException("GeoIP release page version and download URL disagree");
        found.add(new Release(role, month, raw, sha.group(1).toLowerCase(Locale.ROOT)));
      }
    }
    if (found.size() != 1)
      throw new IOException(
          "DB-IP "
              + role
              + " page changed: expected one MMDB release with URL and SHA1, found "
              + found.size());
    return found.getFirst();
  }

  private void get(String raw, OutputStream out, long limit, long deadline) throws IOException {
    for (int redirects = 0; ; redirects++) {
      allowed(raw);
      long remaining = deadline - System.nanoTime();
      if (remaining <= 0) throw new IOException("GeoIP operation timed out");
      Response response =
          transport.get(
              URI.create(raw), Duration.ofNanos(Math.min(remaining, 45_000_000_000L)), out, limit);
      if (response.status() == 200) return;
      if (Set.of(301, 302, 303, 307, 308).contains(response.status())) {
        if (redirects >= 4 || response.location() == null)
          throw new IOException("too many or invalid GeoIP redirects");
        try {
          raw = URI.create(raw).resolve(response.location()).toString();
        } catch (IllegalArgumentException ex) {
          throw new IOException("invalid GeoIP redirect", ex);
        }
        continue;
      }
      throw new IOException("GeoIP download " + raw + ": HTTP " + response.status());
    }
  }

  public Release latest(String role, long deadline) throws IOException {
    if (!Set.of("country", "asn").contains(role))
      throw new IOException("unknown GeoIP role " + role);
    var out = new ByteArrayOutputStream();
    get("https://db-ip.com/db/download/ip-to-" + role + "-lite", out, 1 << 20, deadline);
    return parse(out.toString(StandardCharsets.UTF_8), role);
  }

  public void fetch(Release release, OutputStream out, long deadline) throws IOException {
    get(release.url(), out, 64L << 20, deadline);
  }

  private static final class HttpTransport implements Transport {
    private final HttpClient client =
        HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(10))
            .proxy(
                new ProxySelector() {
                  public List<Proxy> select(URI uri) {
                    return List.of(Proxy.NO_PROXY);
                  }

                  public void connectFailed(URI uri, SocketAddress address, IOException error) {}
                })
            .build();

    public Response get(URI uri, Duration timeout, OutputStream out, long limit)
        throws IOException {
      var request =
          HttpRequest.newBuilder(uri)
              .timeout(timeout)
              .header("User-Agent", "Mozilla/5.0 (compatible; WebAuditJ GeoIP manager)")
              .GET()
              .build();
      CompletableFuture<HttpResponse<Void>> future =
          client.sendAsync(
              request,
              info ->
                  info.statusCode() == 200
                      ? new LimitedHttpBody(out, limit)
                      : HttpResponse.BodySubscribers.replacing(null));
      try {
        var r = future.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
        return new Response(r.statusCode(), r.headers().firstValue("location").orElse(null));
      } catch (InterruptedException ex) {
        future.cancel(true);
        Thread.currentThread().interrupt();
        throw new IOException("GeoIP download interrupted", ex);
      } catch (TimeoutException ex) {
        future.cancel(true);
        throw new IOException("GeoIP download timeout", ex);
      } catch (ExecutionException ex) {
        throw new IOException(
            "GeoIP transfer failed: " + ex.getCause().getMessage(), ex.getCause());
      }
    }
  }
}
