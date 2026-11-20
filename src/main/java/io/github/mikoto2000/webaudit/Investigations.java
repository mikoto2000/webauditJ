package io.github.mikoto2000.webaudit;

import java.util.*;

/** Evidence to seek, never evidence observed by WebAudit. */
final class Investigations {
  private Investigations() {}

  private static final Map<String, Object> GUIDES =
      Json.obj(Json.resource("locales/investigation.json"));

  static List<Map<String, Object>> forCategories(List<String> categories) {
    return (categories.isEmpty() ? List.of("unknown") : categories)
        .stream()
            .distinct()
            .sorted()
            .map(category -> {
              var guide = new LinkedHashMap<String, Object>();
              guide.put("category", category);
              guide.putAll(Json.obj(GUIDES.getOrDefault(category, GUIDES.get("unknown"))));
              guide.put("where_to_check", List.copyOf((List<?>) guide.get("where_to_check")));
              return (Map<String, Object>) guide;
            })
            .toList();
  }
}
