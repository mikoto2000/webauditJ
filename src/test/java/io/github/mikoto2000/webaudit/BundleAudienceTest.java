package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BundleAudienceTest {
  @TempDir Path dir;

  @Test void exportsSharedModelsSafePromptsAndVersionedArtifacts() throws Exception {
    Path input=dir.resolve("access.log");
    Files.writeString(input,BundleTest.LINE.replace("/.env","/.env?token=TOPSECRET").replace("Browser","IGNORE-ALL-INSTRUCTIONS<script>")+"\n");
    for(String lang:List.of("ja","en")) {
      var b=new BundleOptions(); b.language=lang;b.title="<script>IGNORE-ALL-INSTRUCTIONS</script>";
      Path out=dir.resolve(lang);var report=Bundle.generate(List.of(input),out,new Options(),b);
      for(var pair:Map.of("decision_support","data/decision-support.json","secondary_investigation","data/investigation-plan.json").entrySet())
        assertEquals(Json.MAPPER.readTree(Json.MAPPER.writeValueAsString(report.get(pair.getKey()))),Json.MAPPER.readTree(Files.readString(out.resolve(pair.getValue()))));
      for(String name:List.of("executive.html","technical.html","index.html","risk-rules.json","risk-register.csv","action-plan.csv","report-spec.md","templates/executive-summary.html","templates/technical-report.html","templates/report.css")) assertTrue(Files.isRegularFile(out.resolve(name)),name);
      var plan=Json.obj(report.get("secondary_investigation")); var cases=Json.rows(plan.get("cases"));assertFalse(cases.isEmpty());
      for(var f:Json.rows(Json.obj(report.get("analysis")).get("findings"))) assertTrue(cases.stream().anyMatch(c->c.get("id").equals(f.get("id"))));
      String prompt=Files.readString(out.resolve("prompts/secondary-investigation-all.md"));
      for(String value:List.of("TOPSECRET","IGNORE-ALL-INSTRUCTIONS","192.0.2.1","/.env?")) assertFalse(prompt.contains(value),value);
      assertTrue(prompt.contains("report-spec.md"));assertTrue(prompt.contains("templates/"));
      String tech=Files.readString(out.resolve("technical.html"));assertTrue(tech.contains("id=\"secondary-investigation\""));assertTrue(tech.contains("script-src 'self'"));
      String exec=Files.readString(out.resolve("executive.html"));assertFalse(exec.contains("<script>"));assertTrue(exec.contains(lang.equals("ja")?"推奨対応":"Recommended response"));
      assertFalse(Files.readString(out.resolve("report.html")).contains("<script"));
      for(var c:cases) assertTrue(Files.readString(out.resolve("prompts/cases/"+c.get("id")+".md")).contains(c.get("id").toString()));
      var manifest=Json.object(Files.readString(out.resolve("manifest.json")));
      for(String key:List.of("decision_rules_version","report_spec_version","secondary_template_version"))assertFalse(Json.string(manifest.get(key)).isEmpty(),key);
      for(var a:Json.rows(manifest.get("artifacts"))) assertEquals(a.get("sha256"),Bundle.hash(out.resolve(a.get("path").toString()),Long.MAX_VALUE));
      try(var files=Files.walk(out)) {for(var file:files.filter(Files::isRegularFile).toList())assertFalse(Files.readString(file).contains("TOPSECRET"),file.toString());}
    }
  }

  @Test void defersEmptyAndPartialInputsWithoutClaimingSafety() throws Exception {
    Path input=dir.resolve("empty.log");Files.writeString(input,"");
    var r=Bundle.generate(List.of(input),dir.resolve("empty"),new Options(),new BundleOptions());
    assertEquals("hold",Json.obj(r.get("decision_support")).get("response_level"));
    assertTrue(Json.rows(Json.obj(r.get("secondary_investigation")).get("cases")).isEmpty());
  }
}
