package io.github.mikoto2000.webaudit;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CodingErrorAction;

final class Utf8 {
    private Utf8() {}
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
