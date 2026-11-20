package io.github.mikoto2000.webaudit;

import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.stream.Stream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class CorpusTest {
  @TempDir Path dir;

  @TestFactory
  Stream<DynamicTest> matchesGoSyntheticCorpusReports() {
    return Json.rows(Json.resource("corpus-golden.json")).stream()
        .map(row ->
            DynamicTest.dynamicTest(
                Json.string(row.get("name")),
                () -> {
                  Path input = dir.resolve("fixture.log");
                  Files.writeString(
                      input,
                      String.join(
                          "\n",
                          ((List<?>) row.get("lines")).stream().map(Object::toString).toList()));
                  var o = new Options();
                  o.clock = Clock.fixed(Instant.parse("2000-01-01T00:00:00Z"), ZoneOffset.UTC);
                  UpstreamTest.equalJson(
                      EngineTest.normalize(row.get("report"), "fixture.log"),
                      EngineTest.normalize(
                          Engine.analyze(List.of(input), o), input.toAbsolutePath().toString()));
                }));
  }
}
