package io.github.mikoto2000.webaudit;
import java.io.*;
import java.nio.file.*;
import java.util.*;
final class ManagedGeoIP {
    record Opened(GeoIP geo,List<String> warnings){}
    static Opened open(String country,String asn,Path dir,Path legacy,int capacity)throws IOException{
        if(dir==null||!country.isEmpty()&&!asn.isEmpty())return new Opened(GeoIP.open(country,asn,legacy,capacity),List.of());
        try{
            return GeoStore.withCurrent(dir,meta->{
                String c=country,a=asn;for(var d:Json.rows(Json.obj(meta.get("current")).get("databases"))){if("country".equals(d.get("role"))&&c.isEmpty())c=dir.resolve((String)d.get("file")).toString();if("asn".equals(d.get("role"))&&a.isEmpty())a=dir.resolve((String)d.get("file")).toString();}
                GeoIP g=GeoIP.open(c,a,null,capacity);try{apply(g,meta,country,asn);return new Opened(g,List.of());}catch(RuntimeException ex){if(g!=null)g.close();throw ex;}
            });
        }catch(GeoStore.NotInstalled ex){GeoIP g=GeoIP.open(country,asn,legacy,capacity);if(g!=null&&!g.hasReaders()){var warnings=List.copyOf(g.warnings);g.close();return new Opened(null,warnings);}return new Opened(g,List.of());}
        catch(IOException ex){return new Opened(GeoIP.open(country,asn,null,capacity),List.of("Managed GeoIP unavailable; analysis continues without automatic GeoIP: "+ex.getMessage()));}
    }
    private static void apply(GeoIP g,Map<String,Object> meta,String country,String asn){
        var current=Json.obj(meta.get("current"));for(var row:g.metadata()){
            if("country".equals(row.get("role"))&&!country.isEmpty()||"asn".equals(row.get("role"))&&!asn.isEmpty())continue;
            for(var d:Json.rows(current.get("databases")))if(d.get("role").equals(row.get("role"))){row.put("version",d.get("version"));row.put("downloaded_at",d.get("downloaded_at"));row.put("source_url",d.get("url"));row.put("generation",current.get("id"));row.put("last_checked_at",meta.get("last_checked_at"));}
        }
    }
}
