package io.github.mikoto2000.webaudit;

import java.util.*;

final class Behavior {
    final List<String> warnings=new ArrayList<>();
    Behavior(Options options) {}
    void observe(Event e,List<Map<String,Object>> hits) {}
    List<Signal> finish() {return List.of();}
}
