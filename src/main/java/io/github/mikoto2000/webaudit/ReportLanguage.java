package io.github.mikoto2000.webaudit;

import java.util.*;
import java.util.regex.Pattern;

/** Presentation only: callers explicitly select authored text, never source evidence. */
final class ReportLanguage {
  private static final Map<String, Object> JAPANESE = Json.obj(Json.resource("locales/ja.json"));
  private static final Map<String, Object> ENGLISH =
      Json.obj(Json.resource("locales/investigation_en.json"));
  private final String language;

  ReportLanguage(String language) {
    this.language = language;
  }

  String text(String s) {
    var catalog = language.equals("en") ? ENGLISH : JAPANESE;
    if (catalog.containsKey(s)) return catalog.get(s).toString();
    if (language.equals("en")) return s;
    var missing =
        Pattern.compile(
                "^Missing ([a-z_]+) in ([0-9]+) parsed requests reduces related detection"
                    + " coverage$")
            .matcher(s);
    if (missing.matches())
      return "解析済みの"
          + missing.group(2)
          + "件の要求で"
          + text(missing.group(1))
          + "が欠落し、関連する検出範囲が狭まっています";
    var observations =
        Pattern.compile(
                "^([0-9]+) observations in overlapping five-minute event-time window; diversity"
                    + " bounded at 64$")
            .matcher(s);
    if (observations.matches())
      return "重複する5分間のイベント時刻区分で" + observations.group(1) + "件を観測。異なる値は最大64件まで保持";
    return s;
  }

  String outcome(String s) {
    return text(
        switch (s) {
          case "unknown" -> "Unknown outcome";
          case "confirmed_success" -> "Confirmed success";
          case "possible_success" -> "Possible success";
          case "likely_failed" -> "Likely failed";
          case "confirmed_failure" -> "Confirmed failure";
          default -> s;
        });
  }

  String diagnostic(String s) {
    if (s.isEmpty() || language.equals("en")) return text(s);
    String translated = knownDiagnostic(s);
    if (translated != null) return translated;
    for (int at = s.indexOf(": "); at >= 0; at = s.indexOf(": ", at + 2)) {
      translated = knownDiagnostic(s.substring(at + 2));
      if (translated != null) return s.substring(0, at + 2) + translated;
    }
    return "診断情報（原文）: " + s;
  }

  private String knownDiagnostic(String s) {
    String translated = text(s);
    if (!translated.equals(s)) return translated;
    var db =
        Pattern.compile("^GeoIP (country|asn) database (\".*\"): (.*); automatic database ignored$")
            .matcher(s);
    if (db.matches())
      return "GeoIP "
          + text(db.group(1))
          + " DB "
          + db.group(2)
          + "を利用できないため、自動検出したDBを無視しました（詳細は原文）: "
          + db.group(3);
    var lookup = Pattern.compile("^GeoIP (country|asn) lookup failed: (.*)$").matcher(s);
    if (lookup.matches())
      return "GeoIP " + text(lookup.group(1)) + "の検索に失敗しました（詳細は原文）: " + lookup.group(2);
    var directory = Pattern.compile("^directory (.*): (.*)$").matcher(s);
    if (directory.matches())
      return "ディレクトリ " + directory.group(1) + "の読み込みエラー（詳細は原文）: " + directory.group(2);
    String[][] prefixes = {
      {"Invalid error log timezone: ", "エラーログのタイムゾーンが不正です（詳細は原文）: "},
      {"Skipped non-regular input: ", "通常ファイルではない入力を読み飛ばしました: "},
      {
        "Managed GeoIP unavailable; analysis continues without automatic GeoIP: ",
        "管理GeoIPを利用できないため、自動GeoIPなしで解析を続行します（詳細は原文）: "
      },
      {"ambiguous JSON field ", "解釈が競合するJSONフィールド: "},
      {"duplicate JSON field ", "重複したJSONフィールド: "},
      {"invalid JSON: ", "不正なJSON（詳細は原文）: "},
      {"custom regex: ", "カスタム正規表現のエラー（詳細は原文）: "}
    };
    for (var pair : prefixes)
      if (s.startsWith(pair[0])) return pair[1] + s.substring(pair[0].length());
    return null;
  }
}
