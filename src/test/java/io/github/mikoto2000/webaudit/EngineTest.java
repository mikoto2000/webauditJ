package io.github.mikoto2000.webaudit;
import java.util.*;
import java.nio.file.*;
import java.time.*;
import java.util.stream.Stream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
class EngineTest {
    @TempDir Path dir;
    @TestFactory Stream<DynamicTest> matchesEntireGoReports(){return Json.rows(Json.resource("upstream-golden.json")).stream().map(row->DynamicTest.dynamicTest(Json.string(row.get("name")),()->{
        Path input=dir.resolve("fixture.log");Files.writeString(input,String.join("\n",((List<?>)row.get("lines")).stream().map(Object::toString).toList()));
        var o=new Options();o.clock=Clock.fixed(Instant.parse("2000-01-01T00:00:00Z"),ZoneOffset.UTC);
        Object actual=normalize(Engine.analyze(List.of(input),o),input.toAbsolutePath().toString());
        UpstreamTest.equalJson(normalize(row.get("report"),"fixture.log"),actual);
    }));}
    static Object normalize(Object value,String input){
        if(value instanceof String s)return s.replace(input,"<INPUT>");
        if(value instanceof List<?> list)return list.stream().map(v->normalize(v,input)).toList();
        if(value instanceof Map<?,?> map){var out=new TreeMap<String,Object>();map.forEach((k,v)->out.put((String)k,normalize(v,input)));if(out.get("warnings") instanceof List<?> warnings)out.put("warnings",warnings.stream().map(Object::toString).sorted().toList());
            // Wall-clock incident IDs intentionally include the absolute input file.
            if(Boolean.TRUE.equals(out.get("timezone_unknown"))&&out.containsKey("id"))out.put("id","<PATH-DEPENDENT-ID>");
            if("webaudit/2".equals(out.get("schema")))out.put("version","<IMPLEMENTATION-VERSION>");return out;}
        return value;
    }
    @Test void skipsHugeAndInvalidUtf8LinesButRecovers()throws Exception{
        Path p=dir.resolve("access.log");String valid=CorrelatorTest.event(0,404).raw;
        byte[] text=("x".repeat(400)+"\n"+valid+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);Files.write(p,text);var o=new Options();o.maxLineBytes=256;
        var r=Engine.analyze(List.of(p),o);assertEquals(1,Json.number(r.get("requests")));assertEquals(1,Json.number(r.get("unparsed")));assertTrue(Json.bool(r.get("partial")));
    }
    @Test void retainsRepeatsAndDeduplicatesOnlyCompleteFilesWhenRequested()throws Exception{
        Path p=dir.resolve("a.log"),q=dir.resolve("b.log");String data=CorrelatorTest.event(0,404).raw+"\n";Files.writeString(p,data+data);Files.copy(p,q);
        var o=new Options();var r=Engine.analyze(List.of(p,q),o);assertEquals(4,Json.number(r.get("requests")));assertEquals(0,Json.number(r.get("duplicates")));
        o.deduplicateFiles=true;r=Engine.analyze(List.of(p,q),o);assertEquals(2,Json.number(r.get("duplicates")));assertEquals(2,Json.number(Json.rows(r.get("findings")).getFirst().get("count")));
    }
}
