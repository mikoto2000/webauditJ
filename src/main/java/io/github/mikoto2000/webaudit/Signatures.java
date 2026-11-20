package io.github.mikoto2000.webaudit;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Objects;
import com.google.re2j.Pattern;

public final class Signatures {
    public record Detection(List<Map<String,Object>> hits, Normalizer.Normalized normalization) {}
    private record Compiled(Map<String,Object> rule, Pattern regex) {}
    private static final List<Compiled> RULES=Json.rows(Json.resource("rules.json")).stream()
            .map(r->new Compiled(r,Pattern.compile("(?i)"+r.get("pattern")))).toList();
    private Signatures() {}
    public static Detection detect(Event e) {
        var n=Normalizer.normalize(e.target);var hits=new ArrayList<Map<String,Object>>();
        for(var compiled:RULES){var r=compiled.rule();var values=values(r,e,n);
            for(String v:values){
                boolean excluded=false;
                if(r.get("exclude") instanceof List<?> excludes)for(Object x:excludes)if(v.equalsIgnoreCase((String)x)){excluded=true;break;}
                if(!excluded&&compiled.regex().matcher(v).find()){hits.add(r);break;}
            }
        }
        return new Detection(hits,n);
    }
    private static List<String> values(Map<String,Object> r,Event e,Normalizer.Normalized n) {
        var values=new ArrayList<String>();
            switch(Json.string(r.get("field"))){
                case "ua" -> {if(e.ua!=null)values.add(e.ua);}
                case "method" -> {if(e.method!=null)values.add(e.method);}
                case "protocol" -> {if(e.protocol!=null)values.add(e.protocol);}
                default -> {values.addAll(n.variants());if("url_headers".equals(r.get("field"))){values.add(Objects.requireNonNullElse(e.ua,""));values.add(Objects.requireNonNullElse(e.referer,""));}}
            }
        return values;
    }

}
