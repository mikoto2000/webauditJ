package io.github.mikoto2000.webaudit;

import java.util.stream.Stream;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

class LogParserTest {
    @TestFactory Stream<DynamicTest> matchesGoEventsIncludingUpstreamFormats() {
        return Json.rows(Json.resource("parser-golden.json")).stream().map(row -> DynamicTest.dynamicTest(
            Json.string(row.get("input")).substring(0, Math.min(90, Json.string(row.get("input")).length())), () -> {
                if (row.containsKey("error")) {
                    assertThrows(IllegalArgumentException.class, () -> LogParser.parse(Json.string(row.get("input")), Json.string(row.get("file")), Json.number(row.get("line")), Json.string(row.get("custom"))));
                } else {
                    Event e = LogParser.parse(Json.string(row.get("input")), Json.string(row.get("file")), Json.number(row.get("line")), Json.string(row.get("custom")));
                    assertEquals(Json.MAPPER.readTree(Json.MAPPER.writeValueAsString(row.get("event"))),
                            Json.MAPPER.readTree(Json.MAPPER.writeValueAsString(e.toMap())));
                }
            }));
    }
    @Test void rejectsDuplicateKeysAndTrailingData() {
        assertThrows(IllegalArgumentException.class, () -> LogParser.parse("{\"remote_addr\":\"8.8.8.8\",\"remote_addr\":\"1.1.1.1\"}", "x",1,""));
        assertThrows(IllegalArgumentException.class, () -> LogParser.parse("{} {}", "x",1,""));
    }
}
