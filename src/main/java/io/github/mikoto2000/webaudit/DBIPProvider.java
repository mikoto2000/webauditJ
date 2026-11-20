package io.github.mikoto2000.webaudit;
import java.io.*;
import java.net.URI;
import java.time.Duration;
final class DBIPProvider implements GeoSource {
    record Response(int status,String location){}
    interface Transport {Response get(URI uri,Duration timeout,OutputStream out,long limit)throws IOException;}
    DBIPProvider(){}
    DBIPProvider(Transport transport){}
    static void allowed(String raw)throws IOException{throw new IOException("not allowed");}
    static Release parse(String html,String role)throws IOException{throw new IOException("page changed");}
    public Release latest(String role,long deadline)throws IOException{throw new IOException("not implemented");}
    public void fetch(Release release,OutputStream out,long deadline)throws IOException{throw new IOException("not implemented");}
}
