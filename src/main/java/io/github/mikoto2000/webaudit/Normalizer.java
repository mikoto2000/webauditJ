package io.github.mikoto2000.webaudit;

import java.util.List;

public final class Normalizer {
    private Normalizer() {}
    public record Normalized(String original, List<String> variants, List<String> steps, List<String> warnings) {}
    public static Normalized normalize(String input) {
        return new Normalized(input, List.of(input), List.of(), List.of());
    }
}
