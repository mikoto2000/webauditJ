package io.github.mikoto2000.webaudit;

import java.util.*;
import static io.github.mikoto2000.webaudit.Core.*;
import static io.github.mikoto2000.webaudit.SourceMatcher.*;

final class AuraSignatures {
    private final Options options;
    private final List<String> warnings;
    private final Map<String,Map<String,Object>> aura=new HashMap<>();
    AuraSignatures(Options options,List<String> warnings){this.options=options;this.warnings=warnings;}
    private void add(Event e,String id){
        String key=id+"\0"+e.ip+(e.timezoneUnknown?"\0wall:"+e.file:"");var a=aura.get(key);
        if(a==null){if(aura.size()>=options.maxKeys){unique(warnings,"Aura match limit reached; source matches are incomplete");return;}a=Json.map("source","AuraDFIR","rule_id",id,"ip",e.ip,"group",e.ip,"first",e.timezoneUnknown?null:Times.text(e.time),"last",e.timezoneUnknown?null:Times.text(e.time),"count",0L,"events",null);if(e.timezoneUnknown){a.put("timezone_unknown",true);a.put("wall_first",Times.wall(e.time));a.put("wall_last",Times.wall(e.time));}a.put("source","AuraDFIR");aura.put(key,a);}
        a.put("count",Json.number(a.get("count"))+1);
        if(a.get("last")!=null){if(e.time.isBefore(Times.parse((String)a.get("first"))))a.put("first",Times.text(e.time));if(e.time.isAfter(Times.parse((String)a.get("last"))))a.put("last",Times.text(e.time));}
        else {String wall=Times.wall(e.time);if(wall.compareTo((String)a.get("wall_first"))<0)a.put("wall_first",wall);if(wall.compareTo((String)a.get("wall_last"))>0)a.put("wall_last",wall);}
        if(a.get("events")==null)a.put("events",new ArrayList<Map<String,Object>>());var refs=Json.rows(a.get("events"));if(refs.size()<8)refs.add(Json.map("file",e.file,"line",e.line));else a.put("evidence_truncated",true);
    }
    void observe(Event e){
        String target=e.target.replace('İ','i').replace('ı','i');
        for(var r:Json.rows(AURA.get("signatures")))if(re("(?i)"+r.get("pattern"),target))add(e,Json.string(r.get("id")));
        String low=lower(s(e.ua).replace("İ","i\u0307"));for(Object ua:(List<?>)AURA.get("scanner_uas"))if(low.contains((String)ua)){add(e,"scanner_ua");break;}
        for(Object method:(List<?>)AURA.get("methods"))if(s(e.method).equals(method)){add(e,"dangerous_method");break;}
    }
    List<Map<String,Object>> finish(){return aura.values().stream().sorted(Comparator.comparing((Map<String,Object> r)->Json.string(r.get("rule_id"))).thenComparing(r->Json.string(r.get("ip")))).toList();}
}
