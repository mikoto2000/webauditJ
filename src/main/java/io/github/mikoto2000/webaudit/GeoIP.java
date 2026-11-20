package io.github.mikoto2000.webaudit;
import java.util.*;
import java.nio.file.Path;
import java.io.*;
public final class GeoIP implements AutoCloseable {
    public static GeoIP open(String country,String asn,Path legacyDir,int capacity)throws IOException{return new GeoIP();}
    final List<String> warnings=new ArrayList<>();
    public Map<String,Object> lookup(String address){return Map.of();}
    public List<Map<String,Object>> metadata(){return List.of();}
    Map<String,Object> metrics(){return Map.of();}
    public void close()throws IOException{}
}
