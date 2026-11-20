package io.github.mikoto2000.webaudit;

import java.util.*;
import static io.github.mikoto2000.webaudit.RobustStats.outlier;
import java.time.*;
import static io.github.mikoto2000.webaudit.Core.*;

final class Behavior {
    final List<String> warnings=new ArrayList<>();
    private final Options options;
    private final Map<String,Window> windows=new TreeMap<>();
    private final Map<String,Peer> ips=new TreeMap<>();
    private final Map<Long,Peer> hours=new TreeMap<>();
    private final Map<String,Baseline> urls=new HashMap<>();
    private final Baseline global=new Baseline();
    private final List<Signal> signals=new ArrayList<>();
    private OffsetDateTime last;
    private static class Peer {long n,errors,statusN,bytesN;double bytes;Event sample;OffsetDateTime first,last;Peer(Event e){sample=compact(e);first=e.time;last=e.time;}void count(Event e){n++;if(e.time.isBefore(first))first=e.time;if(e.time.isAfter(last))last=e.time;}}
    private static final class Window extends Peer {long n404,auth,login;double level;OffsetDateTime previous;boolean burst;final Set<String> paths=new HashSet<>(),uas=new HashSet<>(),categories=new HashSet<>(),sensitive=new HashSet<>();Window(Event e){super(e);}}
    private static final class Baseline {final List<Double> values=new ArrayList<>();int next;void add(double v){if(values.size()<128)values.add(v);else{values.set(next,v);next=(next+1)%128;}}}
    Behavior(Options options) {this.options=options;}
    private boolean allow(int n){if(n>=options.maxKeys){unique(warnings,"Tracked-key limit reached; behavior/statistical coverage is incomplete");return false;}return true;}
    private void distinct(Set<String> set,String value){String key=digest(value);if(set.contains(key))return;if(set.size()>=64){unique(warnings,"Distinct-value limit reached; diversity counts are lower bounds");return;}set.add(key);}
    private void emit(String id,String description,Event e,long n,String reason,OffsetDateTime start,OffsetDateTime end){if(signals.size()>=options.maxFindings){unique(warnings,"Signal limit reached; findings are incomplete");return;}signals.add(new Signal(behaviorRule(id,description),compact(e),n,reason,start,end));}
    void observe(Event e,List<Map<String,Object>> hits) {
        if(last!=null&&e.time.isBefore(last))unique(warnings,"Input timestamps are out of order; event-time windows retained within key budget, online size baselines and leaky buckets are order-sensitive");last=e.time;
        String host=s(e.host),key=digest(e.ip+"\0"+host);
        for(int shift:new int[]{0,150}){
            String wk=key+"\0"+((e.time.toEpochSecond()-shift)/300)+"/"+shift;Window w=windows.get(wk);
            if(w==null){if(!allow(windows.size()))continue;w=new Window(e);windows.put(wk,w);}w.count(e);
            int status=e.status==null?0:e.status;if(status==404)w.n404++;if(status==401||status==403)w.auth++;
            String path=Normalizer.lower(e.path);if("POST".equals(e.method)&&(path.equals("/login")||path.equals("/signin")||path.endsWith("/wp-login.php")||path.endsWith("/login")))w.login++;
            distinct(w.paths,e.path);if(e.ua!=null)distinct(w.uas,e.ua);
            for(var h:hits){distinct(w.categories,Json.string(h.get("category")));if("sensitive_file".equals(h.get("category")))distinct(w.sensitive,e.path);}
            if(w.previous==null||!e.time.isBefore(w.previous)){if(w.previous!=null)w.level=Math.max(0,w.level-Duration.between(w.previous,e.time).toNanos()/1e9);w.previous=e.time;if(++w.level>300)w.burst=true;}
        }
        Peer p=ips.get(key);if(p==null&&allow(ips.size())){p=new Peer(e);ips.put(key,p);}if(p!=null){p.count(e);if(e.status!=null)p.statusN++;if(e.bytes!=null)p.bytesN++;if(e.status!=null&&e.status>=400)p.errors++;p.bytes+=e.bytes==null?0:e.bytes;}
        long hour=e.time.toEpochSecond()/3600;Peer hp=hours.get(hour);if(hp==null&&allow(hours.size())){hp=new Peer(e);hours.put(hour,hp);}if(hp!=null)hp.count(e);
        if(e.bytes!=null&&e.status!=null){double value=e.bytes;String uk=digest(host+"\0"+s(e.method)+"\0"+e.path+"\0"+e.status);Baseline b=urls.get(uk);if(b==null&&allow(urls.size())){b=new Baseline();urls.put(uk,b);}if(b!=null){if(outlier(value,b.values,4096,5))emit("WS-url-size","Response differs from same URL/status baseline",e,1,"At least 20 prior size samples; >median+6*MAD, >5x median and >4096 bytes difference",e.time,e.time);b.add(value);}
            if(outlier(value,global.values,1<<20,10))emit("WS-size","Unusually large response",e,1,"At least 20 prior samples; robust size threshold plus 1 MiB and 10x effect floors",e.time,e.time);global.add(value);}
    }
    private void windowSignal(Window w,String id,String description,long n){emit(id,description,w.sample,n,n+" observations in overlapping five-minute event-time window; diversity bounded at 64",w.first,w.last);}
    List<Signal> finish() {
        for(Window w:windows.values()){
            if(w.n404>=20)windowSignal(w,"WB-404","Concentrated HTTP 404 responses",w.n404);
            if(w.auth>=20)windowSignal(w,"WB-auth","Concentrated HTTP 401/403 responses",w.auth);
            if(w.login>=20)windowSignal(w,"WB-login","Repeated login endpoint requests",w.login);
            if(w.n>=600)windowSignal(w,"WB-rate","High request rate (may be legitimate)",w.n);
            if(w.burst)windowSignal(w,"WB-burst","Leaky bucket burst (capacity 300, leak 1/s)",w.n);
            if(w.paths.size()>=40&&w.n404+w.auth>=10)windowSignal(w,"WB-paths","Diverse URL probing with errors",w.paths.size());
            if(w.sensitive.size()>=5)windowSignal(w,"WB-sensitive","Multiple distinct sensitive resources probed",w.sensitive.size());
            if(w.uas.size()>=5&&w.paths.size()>=10&&w.n404+w.auth>=10)windowSignal(w,"WB-ua","User-Agent rotation during probing",w.uas.size());
            if(w.categories.size()>=2&&w.n>=8)windowSignal(w,"WB-multi","Multiple suspicious techniques in one activity window",w.categories.size());
        }
        var counts=new ArrayList<Double>();var rates=new ArrayList<Double>();var bytes=new ArrayList<Double>();
        for(Peer p:ips.values()){counts.add((double)p.n);if(p.bytesN==p.n)bytes.add(p.bytes);if(p.statusN>=20)rates.add((double)p.errors/p.statusN);}
        for(Peer p:ips.values()){
            if(outlier(p.n,counts,100,5)||p.bytesN==p.n&&outlier(p.bytes,bytes,1<<20,10))emit("WS-ip","IP request/byte volume peer outlier",p.sample,p.n,"At least 20 peer groups; robust median/MAD and minimum effect size; not proof of exfiltration",p.first,p.last);
            if(p.statusN>=20&&outlier((double)p.errors/p.statusN,rates,0.5,3))emit("WS-errors","IP HTTP-error-rate peer outlier",p.sample,p.n,"At least 20 requests per peer and 20 peers; >0.5 rate difference plus robust threshold",p.first,p.last);
        }
        if(hours.size()>=2){long lo=Collections.min(hours.keySet()),hi=Collections.max(hours.keySet());if(hi-lo<options.maxKeys){var base=new ArrayList<Double>();for(long h=lo;h<=hi;h++)base.add(hours.containsKey(h)?(double)hours.get(h).n:0);for(long h=lo;h<=hi;h++){Peer p=hours.get(h);if(p!=null&&outlier(p.n,base,100,5))emit("WS-hour","Hourly traffic peer outlier",p.sample,p.n,"Observed hours including zero bins; >=20 bins; robust threshold, +100 requests and 5x median",p.first,p.last);}}
            else unique(warnings,"Hourly span exceeds bounded baseline; hourly anomalies withheld");}
        if(ips.size()<20)unique(warnings,"Too few IP peers for request/error-rate statistical inference");return List.copyOf(signals);
    }
}
