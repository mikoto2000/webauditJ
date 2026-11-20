package io.github.mikoto2000.webaudit;
import java.io.*;
import java.nio.file.*;
import java.util.*;
final class ManagedGeoIP {
    record Opened(GeoIP geo,List<String> warnings){}
    static Opened open(String country,String asn,Path dir,Path legacy,int capacity)throws IOException{return new Opened(null,List.of());}
}
