package io.github.mikoto2000.webaudit;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.regex.Pattern;

/** Single-file view of the same masked investigation model and technical presentation. */
final class StandaloneReport {
  private StandaloneReport() {}

  record Result(Map<String, Object> analysis, String html) {}

  static Result generate(List<Path> paths, Options options, BundleOptions bundle)
      throws IOException {
    Path temporary =
        FileSystems.getDefault().supportedFileAttributeViews().contains("posix")
            ? Files.createTempDirectory(
                "webauditJ-standalone-",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            : Files.createTempDirectory("webauditJ-standalone-");
    try {
      Path target = temporary.resolve("report");
      var common = Bundle.generate(paths, target, options, bundle);
      String page =
          embed(
              Files.readString(target.resolve("technical-report.html")),
              target,
              bundle.maxOutputBytes,
              bundle.language);
      return new Result(Json.obj(common.get("analysis")), page);
    } finally {
      // The application owns this freshly created private directory; never follow symlinks.
      ManagedFiles.deleteTree(temporary.getParent(), temporary);
    }
  }

  private static final Pattern LINKS = Pattern.compile("href=\"([^\"]+)\"");
  private static final Pattern EXECUTIVE =
      Pattern.compile("<a href=\"executive-summary\\.html[^\"]*\">(.*?)</a>");

  static String embed(String page, Path dir, long limit, String language) throws IOException {
    page = EXECUTIVE.matcher(page).replaceAll("$1");
    String note =
        language.equals("en")
            ? "This is a standalone technical report. Links save embedded annexes. Use --report-dir"
                  + " for the executive report and a directory of handoff materials."
            : "単一ファイルの技術者向けレポートです。CSV等のリンクから内蔵資料を保存できます。幹部向け報告とフォルダーで引き継ぐ資料一式は --report-dir"
                  + " で出力してください。";
    page = page.replace("<main>", "<main><p class=\"standalone-notice\">" + escape(note) + "</p>");
    var hashes = new ArrayList<String>();
    for (String name : List.of("secondary-plan.js", "secondary-investigation.js")) {
      String script = Files.readString(dir.resolve(name)).replace("\r\n", "\n").replace('\r', '\n');
      if (script.toLowerCase(Locale.ROOT).contains("</script"))
        throw new IOException("Unsafe inline script: " + name);
      hashes.add(
          "'sha256-"
              + Base64.getEncoder()
                  .encodeToString(Bundle.sha().digest(script.getBytes(StandardCharsets.UTF_8)))
              + "'");
      page =
          page.replace("<script src=\"" + name + "\"></script>", "<script>" + script + "</script>");
    }
    page = page.replace("script-src 'self'", "script-src " + String.join(" ", hashes));
    int end = page.indexOf("<script>");
    if (end < 0) throw new IOException("Technical report runtime missing");
    // Only renderer-owned attributes are rewritten, never evidence or script text.
    String body = page.substring(0, end), scripts = page.substring(end);
    var result = new StringBuilder();
    var matches = LINKS.matcher(body);
    long remainingBytes = bytes(page);
    while (matches.find()) {
      String ref = unescape(matches.group(1)), replacement;
      if (ref.startsWith("technical-report.html#")) {
        replacement = "href=\"" + escape(ref.substring("technical-report.html".length())) + "\"";
      } else if (ref.startsWith("#") || ref.contains(":")) {
        replacement = matches.group();
      } else {
        Path relative = Path.of(ref);
        if (ref.isEmpty() || relative.isAbsolute() || relative.normalize().startsWith(".."))
          throw new IOException("Invalid annex reference: " + ref);
        Path annex = dir.resolve(relative);
        long encodedBytes = 4 * ((Files.size(annex) + 2) / 3);
        if (remainingBytes + encodedBytes + 512 > limit)
          throw new IOException("Standalone report byte limit exceeded");
        replacement =
            "download=\""
                + escape(relative.getFileName().toString())
                + "\" href=\"data:application/octet-stream;base64,"
                + Base64.getEncoder().encodeToString(Files.readAllBytes(annex))
                + "\"";
      }
      remainingBytes += bytes(replacement) - bytes(matches.group());
      if (remainingBytes > limit) throw new IOException("Standalone report byte limit exceeded");
      matches.appendReplacement(result, java.util.regex.Matcher.quoteReplacement(replacement));
    }
    matches.appendTail(result);
    result.append(scripts);
    if (remainingBytes > limit) throw new IOException("Standalone report byte limit exceeded");
    return result.toString();
  }

  private static long bytes(String text) {
    return text.getBytes(StandardCharsets.UTF_8).length;
  }

  private static String escape(String text) {
    return text.replace("&", "&amp;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;")
        .replace("<", "&lt;")
        .replace(">", "&gt;");
  }

  private static String unescape(String text) {
    return text.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
  }
}
