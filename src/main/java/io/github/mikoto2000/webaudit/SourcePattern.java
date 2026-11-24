package io.github.mikoto2000.webaudit;

import com.google.re2j.Pattern;
import java.util.*;

/** Necessary literals only reject impossible candidates; RE2 remains the final authority. */
final class SourcePattern {
  private final Pattern regex;
  private final List<String> alternatives;

  SourcePattern(String expression) {
    regex = Pattern.compile(expression);
    List<String> literals;
    try {
      var parser = new Literals(expression);
      literals = parser.expression().required;
      if (parser.at != expression.length()) literals = List.of();
    } catch (UnsupportedOperationException e) {
      literals = List.of();
    }
    alternatives = literals;
  }

  // ASCII folding cannot model RE2's Unicode case equivalences. Delegate all
  // non-ASCII inputs (including unpaired UTF-16 surrogates) directly to RE2.
  static String input(String value) {
    for (int i = 0; i < value.length(); i++) if (value.charAt(i) >= 128) return null;
    return value.toLowerCase(Locale.ROOT);
  }

  boolean possible(String value) {
    return possibleFolded(input(value));
  }

  private boolean possibleFolded(String folded) {
    if (folded == null || alternatives.isEmpty()) return true;
    for (String literal : alternatives) if (folded.contains(literal)) return true;
    return false;
  }

  boolean matches(String value, String folded) {
    return possibleFolded(folded) && regex.matcher(value).find();
  }

  // A deliberately restricted regex reader. Unknown syntax disables filtering
  // for the entire pattern. No inferred literal is used as a positive match.
  private record Node(List<String> required, String exact) {
    static Node literal(String s) {
      return new Node(s.isEmpty() ? List.of() : List.of(s.toLowerCase(Locale.ROOT)), s);
    }
  }

  private static final class Literals {
    final String text;
    int at;

    Literals(String text) {
      this.text = text;
    }

    UnsupportedOperationException unsupported() {
      return new UnsupportedOperationException();
    }

    Node expression() {
      var branches = new ArrayList<Node>();
      branches.add(concat());
      while (at < text.length() && text.charAt(at) == '|') {
        at++;
        branches.add(concat());
      }
      if (branches.size() == 1) return branches.getFirst();
      var required = new LinkedHashSet<String>();
      for (Node branch : branches) {
        if (branch.required.isEmpty()) return new Node(List.of(), null);
        required.addAll(branch.required);
      }
      return new Node(List.copyOf(required), null);
    }

    Node concat() {
      List<String> best = List.of();
      var run = new StringBuilder();
      boolean exact = true;
      var whole = new StringBuilder();
      while (at < text.length() && text.charAt(at) != '|' && text.charAt(at) != ')') {
        Node node = quantified();
        if (node.exact != null) {
          run.append(node.exact);
          whole.append(node.exact);
        } else {
          best = better(best, Node.literal(run.toString()).required);
          run.setLength(0);
          exact = false;
        }
        best = better(best, node.required);
      }
      best = better(best, Node.literal(run.toString()).required);
      return new Node(best, exact ? whole.toString() : null);
    }

    List<String> better(List<String> a, List<String> b) {
      int left = a.stream().mapToInt(String::length).min().orElse(0);
      int right = b.stream().mapToInt(String::length).min().orElse(0);
      return right > left ? b : a;
    }

    Node quantified() {
      Node node = atom();
      if (at == text.length()) return node;
      char c = text.charAt(at);
      boolean optional;
      if (c == '*' || c == '?' || c == '+') {
        optional = c != '+';
        at++;
      } else if (c == '{') {
        int start = ++at;
        while (at < text.length() && Character.isDigit(text.charAt(at))) at++;
        if (start == at) throw unsupported();
        optional = Integer.parseInt(text.substring(start, at)) == 0;
        if (at < text.length() && text.charAt(at) == ',') {
          at++;
          while (at < text.length() && Character.isDigit(text.charAt(at))) at++;
        }
        if (at == text.length() || text.charAt(at++) != '}') throw unsupported();
      } else return node;
      if (at < text.length() && text.charAt(at) == '?') at++;
      return new Node(optional ? List.of() : node.required, null);
    }

    Node atom() {
      char c = text.charAt(at++);
      if (c >= 128) throw unsupported();
      if (c == '(') {
        if (at < text.length() && text.charAt(at) == '?') {
          at++;
          if (at < text.length() && text.charAt(at) == ':') at++;
          else {
            int start = at;
            while (at < text.length() && "imsU-".indexOf(text.charAt(at)) >= 0) at++;
            if (at == start || at == text.length()) throw unsupported();
            if (text.charAt(at) == ')') {
              at++;
              return Node.literal("");
            }
            if (text.charAt(at++) != ':') throw unsupported();
          }
        }
        Node group = expression();
        if (at == text.length() || text.charAt(at++) != ')') throw unsupported();
        return group;
      }
      if (c == '[') {
        if (at < text.length() && text.charAt(at) == '^') at++;
        if (at < text.length() && text.charAt(at) == ']') at++;
        while (at < text.length()) {
          char item = text.charAt(at++);
          if (item == '[') throw unsupported(); // POSIX/nested classes: use RE2.
          if (item == '\\') {
            if (at == text.length()) throw unsupported();
            at++;
          } else if (item == ']') return new Node(List.of(), null);
        }
        throw unsupported();
      }
      if (c == '\\') {
        if (at == text.length()) throw unsupported();
        char escape = text.charAt(at++);
        if ("dDsSwWbBAz".indexOf(escape) >= 0) return new Node(List.of(), null);
        if (escape == 'n') return Node.literal("\n");
        if (escape == 'r') return Node.literal("\r");
        if (escape == 't') return Node.literal("\t");
        if (Character.isLetterOrDigit(escape) || escape >= 128) throw unsupported();
        return Node.literal(String.valueOf(escape));
      }
      if (".^$".indexOf(c) >= 0) return new Node(List.of(), null);
      if ("*+?{}".indexOf(c) >= 0) throw unsupported();
      return Node.literal(String.valueOf(c));
    }
  }
}
