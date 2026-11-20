package io.github.mikoto2000.webaudit;
import java.io.*;
import java.nio.file.Path;
import java.util.Map;
public final class Main {
    public static void main(String[] args){System.exit(run(args,new OutputStreamWriter(System.out),new OutputStreamWriter(System.err)));}
    static int run(String[] args,Writer out,Writer err){return run(args,out,err,System.getenv(),null,null);}
    static int run(String[] args,Writer out,Writer err,Map<String,String> environment,Path legacy,GeoSource source){return 2;}
}
