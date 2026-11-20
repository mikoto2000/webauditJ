package io.github.mikoto2000.webaudit;

import java.util.*;

public final class Correlator {
    final List<String> warnings=new ArrayList<>();
    public Correlator(Options options) {}
    public void add(Event e, Signatures.Detection detection) {}
    public List<Map<String,Object>> finish() { return List.of(); }
}
