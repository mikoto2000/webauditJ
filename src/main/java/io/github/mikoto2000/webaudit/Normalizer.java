package io.github.mikoto2000.webaudit;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CodingErrorAction;
import java.nio.ByteBuffer;
import java.io.ByteArrayOutputStream;

public final class Normalizer {
    private Normalizer() {}
    public record Normalized(String original, List<String> variants, List<String> steps, List<String> warnings) {}
    public static Normalized normalize(String input) {
        var variants = new ArrayList<String>(); variants.add(input);
        var steps = new ArrayList<String>(); var warnings = new ArrayList<String>();
        byte[] cur = input.getBytes(StandardCharsets.UTF_8);
        if (input.contains("\\x")) {
            var b = new ByteArrayOutputStream();
            for (int i = 0; i < cur.length; i++) {
                if (i + 3 < cur.length && cur[i] == '\\' && cur[i+1] == 'x' && hex(cur[i+2]) >= 0 && hex(cur[i+3]) >= 0) {
                    b.write(hex(cur[i+2]) * 16 + hex(cur[i+3])); i += 3;
                } else b.write(cur[i]);
            }
            if (!Arrays.equals(cur, b.toByteArray())) {
                cur = b.toByteArray(); add(variants, decode(cur));
                steps.add("log hexadecimal escape detection variant");
            }
        }
        for (int depth = 0; depth < 2; depth++) {
            var b = new ByteArrayOutputStream(); boolean bad = false;
            for (int i = 0; i < cur.length; i++) {
                if (cur[i] == '%') {
                    if (i+2 < cur.length && hex(cur[i+1]) >= 0 && hex(cur[i+2]) >= 0) {
                        b.write(hex(cur[i+1])*16+hex(cur[i+2])); i+=2; continue;
                    }
                    bad = true;
                }
                b.write(cur[i]);
            }
            if (bad) warnings.add("Invalid percent encoding preserved");
            byte[] next = b.toByteArray();
            if (Arrays.equals(next, cur)) break;
            steps.add("percent-decode detection variant"); add(variants, decode(next)); cur = next;
        }
        for (String v : List.copyOf(variants)) {
            String x = lower(v.replace('\\', '/'));
            if (!x.equals(v)) steps.add("case-fold/backslash detection variant");
            int q = x.indexOf('?');
            if (q >= 0 && x.substring(q).contains("+")) {
                x = x.substring(0,q) + x.substring(q).replace('+',' ');
                steps.add("query plus-to-space detection variant");
            }
            add(variants, x);
        }
        try { StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(cur)); }
        catch (java.nio.charset.CharacterCodingException ex) { warnings.add("Decoded bytes are not valid UTF-8; no Unicode repair inferred"); }
        if (lower(input).contains("%u")) warnings.add("Nonstandard %u encoding is not decoded");
        if (decode(cur).contains("%25")) warnings.add("Maximum decode depth is two");
        return new Normalized(input, List.copyOf(variants), List.copyOf(steps), List.copyOf(warnings));
    }
    private static void add(List<String> values, String s) { if (values.size() < 7 && !values.contains(s)) values.add(s); }
    private static int hex(byte c) { return c >= '0' && c <= '9' ? c-'0' : c >= 'a' && c <= 'f' ? c-'a'+10 : c >= 'A' && c <= 'F' ? c-'A'+10 : -1; }
    static String lower(String s) { var b = new StringBuilder(); s.codePoints().map(Character::toLowerCase).forEach(b::appendCodePoint); return b.toString(); }
    static String decode(byte[] bytes) {
        // Go consumes one byte for each invalid UTF-8 rune; retain that behavior.
        var result = new StringBuilder();
        for (int i = 0; i < bytes.length;) {
            int first = Byte.toUnsignedInt(bytes[i]), n = first < 128 ? 1 : first >= 0xc2 && first < 0xe0 ? 2 : first >= 0xe0 && first < 0xf0 ? 3 : first >= 0xf0 && first < 0xf5 ? 4 : 0;
            if (n > 0 && i+n <= bytes.length) {
                try {
                    var text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes,i,n));
                    result.append(text); i += n; continue;
                } catch (java.nio.charset.CharacterCodingException ignored) {}
            }
            result.append('\ufffd'); i++;
        }
        return result.toString();
    }
}
