package io.github.mikoto2000.webaudit;

import java.util.*;
import java.time.*;
import static io.github.mikoto2000.webaudit.Core.*;

final class GeoAnalysis {
    private final GeoIP g;private final int max;private final TreeMap<String,Map<String,Object>> peers=new TreeMap<>();private boolean truncated;
    GeoAnalysis(GeoIP g,int max){this.g=g;this.max=max;}
    void observe(String raw){String ip=IP.canonical(raw);var p=peers.get(ip);if(p!=null){p.put("requests",Json.number(p.get("requests"))+1);if("public".equals(Json.obj(p.get("info")).get("classification")))g.peerHits++;return;}if(peers.size()>=max){truncated=true;g.skipped++;return;}peers.put(ip,Json.map("ip",ip,"info",g.lookup(ip),"requests",1L));}
    private static final class Group {
        String key,name;long requests;int incidents;final Set<String> ips=new LinkedHashSet<>(),categories=new LinkedHashSet<>(),all=new HashSet<>(),suspicious=new HashSet<>();
        Group(String key,String name){this.key=key;this.name=name;}
        Map<String,Object> map(boolean asn){return Json.map("key",key,"name",name,"requests",requests,"incidents",incidents,"ip_count",all.size(),"suspicious_ip_count",suspicious.size(),"ips",nullable(ips.stream().sorted().toList()),"categories",nullable(categories.stream().sorted().toList()),"multiple_suspicious_ips",asn&&!key.equals("unknown")&&suspicious.size()>=2);}
    }
    static String[] keys(Map<String,Object> x){return new String[]{x.get("country_code")==null?"unknown":x.get("country_code").toString(),x.get("country_name")==null?"unknown":x.get("country_name").toString(),x.get("asn")==null?"unknown":x.get("asn").toString(),x.get("asn_organization")==null?"unknown":x.get("asn_organization").toString()};}
    private static void group(Map<String,Group> groups,String key,String name,String ip,long requests,Map<String,Object> incident){Group row=groups.computeIfAbsent(key,_->new Group(key,name));row.requests+=requests;row.all.add(IP.canonical(ip));if(incident!=null){row.incidents++;row.suspicious.add(IP.canonical(ip));for(Object cat:(List<?>)incident.get("categories"))if(row.categories.size()<64)row.categories.add((String)cat);}if(row.ips.size()<64)row.ips.add(ip);}
    private static List<Map<String,Object>> sorted(Map<String,Group> groups,boolean asn){return groups.values().stream().sorted(Comparator.comparingLong((Group r)->r.requests).reversed().thenComparing(r->r.key)).map(r->r.map(asn)).toList();}
    void finish(Map<String,Object> report){
        var countries=new HashMap<String,Group>();var asns=new HashMap<String,Group>();
        for(var p:peers.values()){String[] k=keys(Json.obj(p.get("info")));String ip=Json.string(p.get("ip"));long n=Json.number(p.get("requests"));group(countries,k[0],k[1],ip,n,null);group(asns,k[2],k[3],ip,n,null);}
        var findings=Json.rows(report.get("findings"));for(var f:findings){String ip=Json.string(f.get("ip"));var x=g.lookup(ip);f.put("geoip",x);String[] k=keys(x);group(countries,k[0],k[1],ip,0,f);group(asns,k[2],k[3],ip,0,f);}
        var similarities=similarities(findings,max);
        report.put("geoip",Json.map("enabled",true,"databases",g.metadata(),"peers",nullable(new ArrayList<>(peers.values())),"countries",sorted(countries,false),"asns",sorted(asns,true),"truncated",truncated,"correlations",similarities.rows(),"correlations_truncated",similarities.truncated(),"context","Investigation context only: shared country or ASN does not establish a shared actor, an attack, or attack success. Counts cover retained parsed peers and WebAudit incidents; upstream alerts are separate. IP/category samples are limited to 64 per group; counts may be lower bounds when truncated."));
        if(truncated){Engine.warn(report,"GeoIP peer limit reached; request/country/ASN counts are lower bounds");report.put("partial",true);}for(String w:g.warnings){Engine.warn(report,w);report.put("partial",true);}
    }
    private static final class Candidate {final Map<String,Object> row;final Set<String> ips=new HashSet<>();final List<String> ids=new ArrayList<>();Candidate(Map<String,Object> row){this.row=row;}}
    private record Similarities(List<Map<String,Object>> rows,boolean truncated){}
    private static Similarities similarities(List<Map<String,Object>> findings,int max){
        var candidates=new HashMap<String,Candidate>();boolean truncated=false;
        for(var f:findings){if(f.get("geoip")==null||Json.obj(f.get("geoip")).get("asn")==null||Json.bool(f.get("timezone_unknown"))||!(f.get("evidence") instanceof List<?> ev)||ev.isEmpty())continue;
            var e=Json.obj(Json.rows(ev).getFirst().get("event"));String path=Json.string(e.get("path"));if(path.isEmpty()||Json.bool(e.get("evidence_truncated"))||Json.bool(e.get("request_malformed")))continue;
            OffsetDateTime first=Times.parse((String)f.get("first")),last=Times.parse((String)f.get("last")),start=Instant.ofEpochSecond(Math.floorDiv(first.toEpochSecond(),300)*300).atOffset(ZoneOffset.UTC),end=start.plusMinutes(5);if(!last.isBefore(end))continue;
            String asn=Json.obj(f.get("geoip")).get("asn").toString();for(Object category:(List<?>)f.get("categories")){
                String key=digest(asn+"\0"+Json.string(f.get("host"))+"\0"+path+"\0"+category+"\0"+Times.text(start));Candidate c=candidates.get(key);
                if(c==null){if(candidates.size()>=max){truncated=true;continue;}c=new Candidate(Json.map("asn",asn,"target_host",f.get("host"),"path",path,"category",category,"window_start",Times.text(start),"window_end",Times.text(end),"basis","Same known ASN, exact recorded path, target host when available, technique category and five-minute UTC interval. Unknown hosts are not verified as the same target. This is an investigation hint, not shared-actor or attack-success evidence.","samples_truncated",false));candidates.put(key,c);}
                c.ips.add(IP.canonical(Json.string(f.get("ip"))));if(c.ids.size()<64)unique(c.ids,Json.string(f.get("id")));else c.row.put("samples_truncated",true);
            }
        }
        var out=new ArrayList<Map<String,Object>>();for(Candidate c:candidates.values()){if(c.ips.size()<2)continue;c.row.put("ip_count",c.ips.size());c.row.put("ips",c.ips.stream().sorted().limit(64).toList());c.row.put("incident_ids",c.ids.stream().sorted().toList());if(c.ips.size()>64)c.row.put("samples_truncated",true);out.add(c.row);}
        out.sort(Comparator.comparing((Map<String,Object> r)->Json.string(r.get("asn"))).thenComparing(r->Times.parse(Json.string(r.get("window_start"))).toInstant()).thenComparing(r->Json.string(r.get("target_host"))).thenComparing(r->Json.string(r.get("path"))).thenComparing(r->Json.string(r.get("category"))));return new Similarities(out,truncated);
    }
}
