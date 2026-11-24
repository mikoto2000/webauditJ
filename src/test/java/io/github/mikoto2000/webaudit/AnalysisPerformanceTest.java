package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import com.google.re2j.Pattern;
import java.util.*;
import org.junit.jupiter.api.Test;

class AnalysisPerformanceTest {
  @Test
  void filtersOnlyWhenEveryRegexAlternativeRequiresALiteral() {
    assertFalse(new SourcePattern("(?i)(union.*select|sleep[ (])").possible("ordinary"));
    assertTrue(new SourcePattern("(?i)(union.*select|sleep[ (])").possible("UNION SELECT"));
    for (String pattern :
        List.of("a*", "(foo|[0-9]+)", "(?:foo)?", "(?:foo){0,2}", "(?:foo|)", "\\Qfoo|bar\\E"))
      assertTrue(new SourcePattern(pattern).possible("123"), pattern);
  }

  @Test
  void agreesWithRe2OnBundledPatternsAndGeneratedInputs() throws Exception {
    var patterns = new LinkedHashSet<String>();
    for (var r : Json.rows(Json.resource("rules.json"))) patterns.add("(?i)" + r.get("pattern"));
    for (var r : Json.rows(SourceMatcher.AURA.get("signatures")))
      patterns.add("(?i)" + r.get("pattern"));
    for (String name : List.of("bad_user_agents.regex.txt", "thinkphp_cve_2018-20062.txt")) {
      try (var in = getClass().getResourceAsStream("/upstream/data/" + name)) {
        new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8)
            .lines()
            .map(String::strip)
            .filter(s -> !s.isEmpty() && !s.startsWith("#"))
            .forEach(patterns::add);
      }
    }
    patterns.addAll(
        List.of(
            "(?i)k",
            "(?i)s",
            "(?i)(foo|bar)?baz",
            "a{0,3}b",
            "[[:alpha:]]+",
            "(?i:foo)|BAR",
            "\\x66oo",
            "a\\Q.\\Eb",
            "ab+c",
            "(foo|bar){2,4}",
            "foo|"));
    var inputs =
        new ArrayList<>(
            List.of(
                "",
                "normal",
                "UNION SELECT",
                "sleep(10)",
                "${jndi:ldap://x}",
                "/.env",
                "foobar",
                "baz",
                "K",
                "ſ",
                "İı",
                "\ud800",
                "a.b",
                "bb",
                "FOO",
                "barbar"));
    for (var r : Json.rows(Json.resource("detection-golden.json")))
      inputs.add(Json.string(r.get("input")));
    var random = new Random(41);
    String alphabet = "abfoFO019/.*?[]{}();|'\\%$+-_ =";
    for (int i = 0; i < 500; i++) {
      var s = new StringBuilder();
      for (int j = random.nextInt(100); j > 0; j--)
        s.append(alphabet.charAt(random.nextInt(alphabet.length())));
      inputs.add(s.toString());
    }
    int filtered = 0;
    for (String p : patterns) {
      var expected = Pattern.compile(p);
      var actual = new SourcePattern(p);
      if (!actual.possible("Mozilla/5.0 /api/items")) filtered++;
      for (String s : inputs)
        assertEquals(
            expected.matcher(s).find(), actual.matches(s, SourcePattern.input(s)), p + " : " + s);
    }
    assertTrue(filtered > 30, "must filter useful real rules, not only delegate to RE2");
  }

  @Test
  void reusableStatisticsPreserveThresholdsAndArrivalOrder() {
    var random = new Random(41);
    var scratch = new double[128];
    for (int count = 0; count <= 128; count++) {
      var base = new ArrayList<Double>();
      for (int i = 0; i < count; i++) base.add((double) random.nextInt(10000));
      var original = List.copyOf(base);
      for (double value : List.of(0.0, 100.0, 10000.0, 1000000.0, 1e9)) {
        for (double floor : List.of(0.0, 4096.0, 1048576.0))
          assertEquals(
              RobustStats.outlier(value, base, floor, 5),
              RobustStats.outlier(value, base, floor, 5, scratch));
      }
      assertEquals(original, base);
    }
    var flat = new ArrayList<>(Collections.nCopies(128, 100.0));
    assertFalse(RobustStats.outlier(4196, flat, 4096, 5, scratch));
    assertTrue(RobustStats.outlier(4197, flat, 4096, 5, scratch));
  }
}
