package io.github.mikoto2000.webaudit;

public final class LogParser {
    private LogParser() {}
    public static Event parse(String text, String file, long line, String custom) {
        throw new IllegalArgumentException("unrecognized layout");
    }
}
