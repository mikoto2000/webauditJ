package io.github.mikoto2000.webaudit;
import java.io.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
final class DatabaseManager {
    final Path dir;GeoSource source;Clock clock=Clock.systemUTC();long maxDatabase=256L<<20;
    interface Fault {void at(String point)throws IOException;}
    Fault fault=point->{};
    record Result(Map<String,Object> metadata,List<String> changed,List<String> warnings){}
    DatabaseManager(Path dir,GeoSource source){this.dir=dir;this.source=source;}
    Result reconcile(boolean update)throws IOException{throw new IOException("not implemented");}
    void rollback()throws IOException{throw new IOException("not implemented");}
}
