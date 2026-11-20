package io.github.mikoto2000.webaudit;

import java.time.*;
import java.time.format.*;
import java.time.temporal.ChronoField;
import java.util.Locale;

final class Times {
    static final DateTimeFormatter APACHE = new DateTimeFormatterBuilder().parseCaseSensitive().appendPattern("dd/MMM/uuuu:HH:mm:ss xx").toFormatter(Locale.ENGLISH).withResolverStyle(ResolverStyle.STRICT);
    static final DateTimeFormatter APACHE_ERROR = new DateTimeFormatterBuilder().appendPattern("MMM d HH:mm:ss").optionalStart().appendFraction(ChronoField.NANO_OF_SECOND,0,9,true).optionalEnd().appendPattern(" uuuu").toFormatter(Locale.ENGLISH);
    private Times() {}
    static OffsetDateTime parse(String s) {
        try { return OffsetDateTime.parse(s,APACHE); }
        catch (DateTimeException e) { return OffsetDateTime.parse(s); }
    }
    static String text(OffsetDateTime t) { return t==null ? null : DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(t); }
    static String wall(OffsetDateTime t) { return DateTimeFormatter.ISO_LOCAL_DATE_TIME.format(t); }
    static String instant(Instant t) { return t==null ? null : text(t.atOffset(ZoneOffset.UTC)); }
}
