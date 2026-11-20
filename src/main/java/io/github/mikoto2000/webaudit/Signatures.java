package io.github.mikoto2000.webaudit;

import java.util.List;
import java.util.Map;

public final class Signatures {
    public record Detection(List<Map<String,Object>> hits, Normalizer.Normalized normalization) {}
    private Signatures() {}
    public static Detection detect(Event event) { return new Detection(List.of(),Normalizer.normalize(event.target)); }
}
