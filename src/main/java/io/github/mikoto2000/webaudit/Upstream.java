package io.github.mikoto2000.webaudit;

import java.util.*;

final class Upstream {
    final List<String> warnings=new ArrayList<>();
    final List<Map<String,Object>> alerts=new ArrayList<>();
    Upstream(Options options) {}
    void observe(Event event) {}
    List<Map<String,Object>> auraMatches(){return List.of();}
}
