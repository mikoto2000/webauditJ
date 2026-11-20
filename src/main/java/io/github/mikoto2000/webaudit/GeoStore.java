package io.github.mikoto2000.webaudit;
import java.io.*;
import java.nio.file.*;
import java.util.*;
final class GeoStore {
    static final class NotInstalled extends IOException {NotInstalled(){super("GeoIP databases are not installed; run 'webauditJ geoip download'");}}
    interface LockedRead<T>{T read(Map<String,Object> metadata)throws IOException;}
    static <T>T withCurrent(Path dir,LockedRead<T> read)throws IOException{throw new NotInstalled();}
    static AutoCloseable lock(Path dir)throws IOException{return ()->{};}
}
