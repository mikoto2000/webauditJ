package io.github.mikoto2000.webaudit;

import java.util.*;
import java.time.*;
import static io.github.mikoto2000.webaudit.Core.*;
import static io.github.mikoto2000.webaudit.SourceMatcher.*;

final class Upstream {
    final List<String> warnings=new ArrayList<>();
    final List<Map<String,Object>> alerts=new ArrayList<>();
    private final Options options;
    private final Map<String,Bucket> buckets=new HashMap<>();
    private final Map<String,Suppression> blocked=new HashMap<>();
    private final Map<String,Map<String,Object>> aura=new HashMap<>();
    private long observed;private int distinctCount;
    private static final class Bucket {int capacity;double leak,tokens;String domain;OffsetDateTime first,last;long count;final Set<String> seen=new HashSet<>();final List<Map<String,Object>> refs=new ArrayList<>();}
    private record Suppression(OffsetDateTime until,String domain) {}
    Upstream(Options options) {this.options=options;}
    private static double duration(String s){if(s.isEmpty()||s.equals("0"))return 0;var m=com.google.re2j.Pattern.compile("([0-9.]+)(ns|us|µs|ms|s|m|h)").matcher(s);double sum=0;int end=0;while(m.find()){if(m.start()!=end)return 0;end=m.end();sum+=Double.parseDouble(m.group(1))*switch(m.group(2)){case "ns"->1e-9;case "us","µs"->1e-6;case "ms"->0.001;case "m"->60;case "h"->3600;default->1;};}return end==s.length()?sum:0;}
    private static double seconds(OffsetDateTime a,OffsetDateTime b){var d=Duration.between(a,b);return d.getSeconds()+d.getNano()/1e9;}
    private void reset(String key){Bucket b=buckets.remove(key);if(b!=null)distinctCount-=b.seen.size();}
    private static String domain(Event e){return e.timezoneUnknown?"wall:"+e.file:"instant";}
    private static Map<String,Object> alert(Event e,String id,String group,Bucket b) {
        String clipped=clip(group,4096);var a=Json.map("source","hub","rule_id",id,"ip",e.ip,"group",clipped,"first",e.timezoneUnknown?null:Times.text(b.first),"last",e.timezoneUnknown?null:Times.text(b.last),"count",b.count,"events",nullable(new ArrayList<>(b.refs)));
        if(!clipped.equals(group))a.put("evidence_truncated",true);if(e.timezoneUnknown){a.put("timezone_unknown",true);a.put("wall_first",Times.wall(b.first));a.put("wall_last",Times.wall(b.last));}return a;
    }
    void observe(Event e) {
        observed++;String domain=domain(e);
        if(observed%5000==0){for(String key:new ArrayList<>(buckets.keySet())){Bucket b=buckets.get(key);if(!b.domain.equals(domain)||b.leak<=0)continue;double tokens=b.tokens;if(e.time.isAfter(b.last))tokens+=seconds(b.last,e.time)/b.leak;if(tokens+1e-9>=b.capacity)reset(key);}}
        observeAura(e);View view=view(e);
        for(var r:RULES){if(!Json.bool(r.get("supported"))||!matches(r,e,view))continue;
            String id=Json.string(r.get("name")),group=group(e,Json.string(r.get("groupby"))),key=digest(id+"\0"+group+(e.timezoneUnknown?"\0"+domain:""));
            int capacity=(int)Json.number(r.get("capacity"));double leak=duration(Json.string(r.get("leakspeed"))),blackhole=duration(Json.string(r.get("blackhole")));
            Bucket b=buckets.get(key);if(b!=null&&seconds(b.last,e.time)>(capacity+1)*leak){reset(key);b=null;}
            if(b==null){if(buckets.size()+blocked.size()>=options.maxKeys){unique(warnings,"Upstream state limit reached; source alerts are incomplete");continue;}b=new Bucket();b.capacity=capacity;b.leak=leak;b.domain=domain;b.tokens=capacity;b.first=e.time;b.last=e.time;buckets.put(key,b);}
            String distinct=Json.string(r.get("distinct"));if(!distinct.isEmpty()){String value=digest(field(e,distinct));if(b.seen.contains(value))continue;if(distinctCount>=options.maxKeys*8){unique(warnings,"Upstream distinct limit reached; source alerts are incomplete");continue;}b.seen.add(value);distinctCount++;}
            if(e.time.isBefore(b.last))unique(warnings,"Upstream event time moved backwards; source bucket parity requires ordered input");
            if(leak>0&&e.time.isAfter(b.last))b.tokens=Math.min(capacity,b.tokens+seconds(b.last,e.time)/leak);
            b.last=e.time;b.count++;b.refs.add(Json.map("file",e.file,"line",e.line));int cache=capacity,cacheSize=(int)Json.number(r.get("cache_size"));if(cacheSize>0&&cacheSize<=cache)cache=cacheSize;if(b.refs.size()>cache+1&&cache>0)b.refs.removeFirst();
            if(!"trigger".equals(r.get("type"))&&b.tokens>=1){b.tokens--;continue;}
            Suppression suppression=blocked.get(key);if(suppression==null||!e.time.isBefore(suppression.until())){
                if(alerts.size()>=options.maxFindings)unique(warnings,"Upstream alert limit reached; source alerts are incomplete");
                else {var a=alert(e,id,group,b);if(id.equals("crowdsecurity/http-technology-probing"))a.put("metadata",Json.map("target_technology",lookupTag("technology_probing.json",view.full())));
                    if(id.equals("crowdsecurity/http-cve-probing"))for(var row:rows("trendy_cves_uris.json"))if(view.full().contains(Json.string(row.get("uri")))){a.put("metadata",Json.map("cve",row.get("cve")));break;}alerts.add(a);}
                if(blackhole>0)blocked.put(key,new Suppression(e.time.plusNanos((long)(blackhole*1e9)),domain));
            }reset(key);
        }
        blocked.entrySet().removeIf(entry->entry.getValue().domain().equals(domain)&&!e.time.isBefore(entry.getValue().until()));
    }
    private void auraAdd(Event e,String id){
        String key=id+"\0"+e.ip+(e.timezoneUnknown?"\0wall:"+e.file:"");var a=aura.get(key);
        if(a==null){if(aura.size()>=options.maxKeys){unique(warnings,"Aura match limit reached; source matches are incomplete");return;}var b=new Bucket();b.first=e.time;b.last=e.time;a=alert(e,id,e.ip,b);a.put("source","AuraDFIR");aura.put(key,a);}
        a.put("count",Json.number(a.get("count"))+1);
        if(a.get("last")!=null){if(e.time.isBefore(Times.parse((String)a.get("first"))))a.put("first",Times.text(e.time));if(e.time.isAfter(Times.parse((String)a.get("last"))))a.put("last",Times.text(e.time));}
        else {String wall=Times.wall(e.time);if(wall.compareTo((String)a.get("wall_first"))<0)a.put("wall_first",wall);if(wall.compareTo((String)a.get("wall_last"))>0)a.put("wall_last",wall);}
        if(a.get("events")==null)a.put("events",new ArrayList<Map<String,Object>>());var refs=Json.rows(a.get("events"));if(refs.size()<8)refs.add(Json.map("file",e.file,"line",e.line));else a.put("evidence_truncated",true);
    }
    private void observeAura(Event e){
        String target=e.target.replace('İ','i').replace('ı','i');
        for(var r:Json.rows(AURA.get("signatures")))if(re("(?i)"+r.get("pattern"),target))auraAdd(e,Json.string(r.get("id")));
        String low=lower(s(e.ua).replace("İ","i\u0307"));for(Object ua:(List<?>)AURA.get("scanner_uas"))if(low.contains((String)ua)){auraAdd(e,"scanner_ua");break;}
        for(Object method:(List<?>)AURA.get("methods"))if(s(e.method).equals(method)){auraAdd(e,"dangerous_method");break;}
    }
    List<Map<String,Object>> auraMatches(){return aura.values().stream().sorted(Comparator.comparing((Map<String,Object> r)->Json.string(r.get("rule_id"))).thenComparing(r->Json.string(r.get("ip")))).toList();}
}
