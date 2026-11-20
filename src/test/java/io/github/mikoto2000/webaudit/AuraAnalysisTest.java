package io.github.mikoto2000.webaudit;
import java.util.*;
import java.util.stream.Stream;
import org.junit.jupiter.api.*;
class AuraAnalysisTest {
    @TestFactory Stream<DynamicTest> matchesGoCaseAggregations(){return Json.rows(Json.resource("upstream-golden.json")).stream().map(row->DynamicTest.dynamicTest(Json.string(row.get("name")),()->{
        var a=new AuraAnalysis(new Options());long line=0;for(Object text:(List<?>)row.get("lines")){line++;try{a.observe(LogParser.parse((String)text,"fixture.log",line,""));}catch(IllegalArgumentException ignored){}}
        UpstreamTest.equalJson(Json.obj(row.get("report")).get("aura_analysis"),Core.nullable(a.finish()));
    }));}
}
