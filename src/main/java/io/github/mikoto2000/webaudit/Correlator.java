package io.github.mikoto2000.webaudit;

import java.util.*;
import java.time.OffsetDateTime;
import static io.github.mikoto2000.webaudit.Core.*;

public final class Correlator {
    final List<String> warnings=new ArrayList<>();
    private final Options options;
    private final Map<String,Incident> items=new HashMap<>();
    private int evidenceBytes;
    static final class Resource {OffsetDateTime blocked;final List<OffsetDateTime> good=new ArrayList<>();}
    static final class Sample {final Event event;final Normalizer.Normalized n;Sample(Event e,Normalizer.Normalized n){this.event=e;this.n=n;}Map<String,Object> map(){return Json.map("event",event.toMap(),"normalization",normalized(n));}}
    static final class Incident {
        Event sample;String id,phase,severity="low";OffsetDateTime first,last;long count,blocked,good;int score;
        final List<Map<String,Object>> rules=new ArrayList<>();final List<String> categories=new ArrayList<>(),reasons=new ArrayList<>();
        final List<Sample> evidence=new ArrayList<>();final Map<String,Resource> resources=new HashMap<>();
    }
    public Correlator(Options options) {this.options=options;}
    static String family(Map<String,Object> r) {
        String category=Json.string(r.get("category")),id=Json.string(r.get("id"));
        return switch(category){case "sensitive_file","cve_probe","iis_aspnet","recon_probe","scanner"->"reconnaissance";case "webshell"->"webshell_probe";default->id.startsWith("WB-")||id.startsWith("WS-")?id:"exploitation_attempt";};
    }
    private Incident get(Event e,String group) {
        String key=digest(e.ip+"\0"+s(e.host)+"\0"+s(e.ua)+"\0"+group+"\0"+(e.time.toEpochSecond()/300)+(e.timezoneUnknown?"\0wall:"+e.file:""));
        if(items.containsKey(key))return items.get(key);
        if(items.size()>=options.maxFindings){unique(warnings,"Incident limit reached; incident counts and evidence are incomplete");return null;}
        Incident f=new Incident();f.sample=compact(e);f.id=id(key);f.first=e.time;f.last=e.time;f.phase=group;items.put(key,f);return f;
    }
    public void add(Event e,Signatures.Detection detection) {
        var groups=new TreeMap<String,List<Map<String,Object>>>();
        for(var r:detection.hits())groups.computeIfAbsent(family(r),_->new ArrayList<>()).add(r);
        for(var group:groups.entrySet()){
            Incident f=get(e,group.getKey());if(f==null)continue;f.count++;
            if(e.time.isBefore(f.first))f.first=e.time;if(e.time.isAfter(f.last))f.last=e.time;
            for(var r:group.getValue())addRule(f,r);addEvidence(f,e,detection.normalization());
            int status=e.status==null?0:e.status;if(status==403||status==404)f.blocked++;if(status>=200&&status<300)f.good++;
            if(group.getValue().stream().anyMatch(r->"sensitive_file".equals(r.get("category")))){
                String key=digest(e.path);Resource res=f.resources.get(key);
                if(res==null&&f.resources.size()<128){res=new Resource();f.resources.put(key,res);}
                if(res!=null){if((status==403||status==404)&&(res.blocked==null||e.time.isBefore(res.blocked)))res.blocked=e.time;
                    if(status>=200&&status<300&&e.bytes!=null&&e.bytes>0&&res.good.size()<8)res.good.add(e.time);}
            }
        }
    }
    void addSignal(Signal s) {
        Incident f=get(s.event(),family(s.rule()));if(f==null)return;addRule(f,s.rule());f.count=Math.max(f.count,s.count());
        if(s.start().isBefore(f.first))f.first=s.start();if(s.end().isAfter(f.last))f.last=s.end();unique(f.reasons,s.reason());
        if(f.evidence.isEmpty())addEvidence(f,s.event(),Normalizer.normalize(s.event().target));
    }
    private static void addRule(Incident f,Map<String,Object> r) {
        if(f.rules.stream().anyMatch(x->x.get("id").equals(r.get("id"))))return;
        f.rules.add(r);unique(f.categories,Json.string(r.get("category")));f.score=Math.min(100,f.score+weight(Json.string(r.get("severity"))));
        if(weight(Json.string(r.get("severity")))>weight(f.severity))f.severity=Json.string(r.get("severity"));unique(f.reasons,Json.string(r.get("description")));
    }
    private void addEvidence(Incident f,Event e,Normalizer.Normalized n) {
        Sample value=new Sample(compact(e),compact(n));int delta=evidenceSize(value.event,value.n);
        if(f.evidence.size()>=8){Sample old=f.evidence.get(7);delta-=evidenceSize(old.event,old.n);}
        if(evidenceBytes+delta>options.maxEvidenceBytes){unique(warnings,"Evidence-byte limit reached; samples are incomplete, use file/line references and original input logs");return;}
        evidenceBytes+=delta;if(f.evidence.size()<8)f.evidence.add(value);else f.evidence.set(7,value);
    }
    private static Map<String,Object> outcome(Incident f) {
        var reasons=new ArrayList<>(List.of("Access logs show requests and response metadata, not server-side execution or returned content"));
        var missing=new ArrayList<>(List.of("Response content and expected resource semantics","Request body, application/authentication audit trail","Backend/proxy status mapping and filesystem/process/network evidence"));
        var next=new ArrayList<>(List.of("Inspect the referenced original logs and confirm request routing and proxy configuration","Correlate application/authentication and error logs for the same time and resource","For payload probes inspect server files, processes and outbound connections"));
        String verdict="unknown";double confidence=0.2;
        if(f.sample.timezoneUnknown)missing.add("Verified timezone and cross-log time alignment");
        else {
            boolean possible=f.resources.values().stream().anyMatch(r->r.blocked!=null&&r.good.stream().filter(t->t.isAfter(r.blocked)).count()>=2);
            if(possible){verdict="possible_success";confidence=0.55;reasons.add("Same sensitive resource changed from blocked/not-found to repeated nonempty 2xx responses; soft-404, redirects, generic pages or legitimate changes remain possible");next.add("Verify actual returned sensitive bytes against a nonexistent-path response; preserve response/application evidence");}
            else if(f.blocked>=3&&f.blocked==f.count){verdict="likely_failed";confidence=0.5;reasons.add("All observed responses in this activity were blocked/not-found, with at least three observations; status mapping and unobserved attempts prevent confirmation");}
        }
        return Json.map("verdict",verdict,"confidence",confidence,"reasons",reasons,"missing",missing,"next",next);
    }
    private static Map<String,Object> toMap(Incident f) {
        var rules=f.rules.stream().sorted(Comparator.comparing(r->Json.string(r.get("id")))).toList();var categories=f.categories.stream().sorted().toList();
        var m=Json.map("id",f.id,"ip",f.sample.ip,"host",f.sample.host,"user_agent",f.sample.ua,"first",f.sample.timezoneUnknown?null:Times.text(f.first),"last",f.sample.timezoneUnknown?null:Times.text(f.last),"count",f.count,"severity",f.severity,"attack_score",f.score,"phase",f.phase,"rules",nullable(rules),"categories",nullable(categories),"correlation",List.of("Same recorded peer IP, target host (when available), User-Agent, technique family and five-minute event-time partition; this is a hypothesis, not verified identity"),"reasons",nullable(f.reasons),"evidence",nullable(f.evidence.stream().map(Sample::map).toList()),"outcome",outcome(f));
        if(f.sample.timezoneUnknown)m.put("timezone_unknown",true);return m;
    }
    public List<Map<String,Object>> finish() {
        var values=new ArrayList<>(items.values());values.sort((a,b)->{boolean ap=outcome(a).get("verdict").equals("possible_success"),bp=outcome(b).get("verdict").equals("possible_success");if(ap!=bp)return ap?-1:1;if(a.score!=b.score)return Integer.compare(b.score,a.score);int t=a.first.toInstant().compareTo(b.first.toInstant());return t!=0?t:a.id.compareTo(b.id);});
        return values.stream().map(Correlator::toMap).toList();
    }
}
