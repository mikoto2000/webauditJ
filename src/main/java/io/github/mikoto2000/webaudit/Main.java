package io.github.mikoto2000.webaudit;
import java.io.*;
import java.nio.file.Path;
import java.util.Map;
import java.util.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import picocli.CommandLine;
public final class Main {
    private Main(){}
    public static void main(String[] args){var out=new BufferedWriter(new OutputStreamWriter(System.out,StandardCharsets.UTF_8));var err=new BufferedWriter(new OutputStreamWriter(System.err,StandardCharsets.UTF_8));int code=run(args,out,err);try{out.flush();err.flush();}catch(IOException ex){code=1;}System.exit(code);}
    static int run(String[] args,Writer out,Writer err){return run(args,out,err,System.getenv(),legacyDirectory(),null);}
    @CommandLine.Command(name="webauditJ",description="Offline HTTP log investigation. Inputs: files, gzip files or directories.")
    static final class Arguments {
        @CommandLine.Parameters(arity="0..*",paramLabel="INPUT") List<Path> inputs=new ArrayList<>();
        @CommandLine.Option(names="-o",paramLabel="PATH") Path output;
        @CommandLine.Option(names={"--format","-format"}) String format="";
        @CommandLine.Option(names={"--verbose","-verbose"}) boolean verbose;
        @CommandLine.Option(names={"--version","-version"}) boolean version;
        @CommandLine.Option(names={"--help","-help","-h"}) boolean help;
        @CommandLine.Option(names={"--dedup-files","-dedup-files"}) boolean dedup;
        @CommandLine.Option(names={"--geoip-country","-geoip-country"}) String country="";
        @CommandLine.Option(names={"--geoip-asn","-geoip-asn"}) String asn="";
        @CommandLine.Option(names={"--log-regex","-log-regex"}) String regex="";
        @CommandLine.Option(names={"--error-timezone","-error-timezone"}) String timezone="";
        @CommandLine.Option(names={"--max-line-bytes","-max-line-bytes"}) int maxLine=65536;
        @CommandLine.Option(names={"--max-file-bytes","-max-file-bytes"}) long maxFile=8589934592L;
        @CommandLine.Option(names={"--max-keys","-max-keys"}) int maxKeys=4096;
        @CommandLine.Option(names={"--max-findings","-max-findings"}) int maxFindings=2000;
        @CommandLine.Option(names={"--max-evidence-bytes","-max-evidence-bytes"}) int maxEvidence=33554432;
    }
    private static void line(Writer out,String text)throws IOException{out.write(text);out.write('\n');}
    static int run(String[] args,Writer out,Writer err,Map<String,String> environment,Path legacy,GeoSource source){
        try{
            if(args.length>0&&args[0].equals("geoip"))return geoip(Arrays.copyOfRange(args,1,args.length),out,err,environment,source);
            var a=new Arguments();var command=new CommandLine(a).setPosixClusteredShortOptionsAllowed(false).setExpandAtFiles(false).setOut(new PrintWriter(out)).setErr(new PrintWriter(err));
            try{command.parseArgs(args);}catch(CommandLine.ParameterException ex){line(err,Reports.terminal(ex.getMessage()));return 2;}
            if(a.version){line(out,"WebAuditJ "+Engine.VERSION+" (rules "+Engine.RULES_VERSION+")");return 0;}
            if(a.help||a.inputs.isEmpty()){command.usage(new PrintWriter(err,true));return a.help?0:2;}
            if(a.maxEvidence<512||a.maxEvidence>1<<30||a.maxLine<64||a.maxLine>16<<20||a.maxFile<1||a.maxFile>1L<<50||a.maxKeys<1||a.maxKeys>1_000_000||a.maxFindings<1||a.maxFindings>100_000){line(err,"Invalid resource limits (see --help)");return 2;}
            if(!a.format.isEmpty()&&!Set.of("html","json","csv").contains(a.format)){line(err,"--format must be html, json or csv");return 2;}
            if(!a.regex.isEmpty()){try{var regex=com.google.re2j.Pattern.compile(a.regex);for(String name:List.of("ip","time","target"))if(!regex.namedGroups().containsKey(name)){line(err,"--log-regex requires named group "+name);return 2;}}catch(IllegalArgumentException ex){line(err,"Invalid --log-regex: "+ex.getMessage());return 2;}}
            if(!a.timezone.isEmpty())try{ZoneId.of(a.timezone);}catch(DateTimeException ex){line(err,"Invalid --error-timezone: "+ex.getMessage());return 2;}
            if(a.output!=null&&Files.exists(a.output,LinkOption.NOFOLLOW_LINKS)){line(err,"Output must be a new file; existing paths and input files are never overwritten");return 2;}
            Path directory=null;var geoWarnings=new ArrayList<String>();try{directory=Path.of(GeoPaths.resolve(os(),environment));}catch(IllegalArgumentException ex){if(a.country.isEmpty()||a.asn.isEmpty())geoWarnings.add(ex.getMessage());}
            ManagedGeoIP.Opened opened;try{opened=ManagedGeoIP.open(a.country,a.asn,directory,legacy,a.maxKeys);}catch(IOException ex){line(err,Reports.terminal(ex.getMessage()));return 2;}geoWarnings.addAll(opened.warnings());
            try(var geo=opened.geo()){
                var o=new Options();o.maxKeys=a.maxKeys;o.maxLineBytes=a.maxLine;o.maxFileBytes=a.maxFile;o.maxFindings=a.maxFindings;o.maxEvidenceBytes=a.maxEvidence;o.deduplicateFiles=a.dedup;o.errorTimezone=a.timezone;o.logRegex=a.regex;o.geoIP=geo;
                var report=Engine.analyze(a.inputs,o);for(String warning:geoWarnings){@SuppressWarnings("unchecked")var warnings=(List<String>)report.get("warnings");warnings.add(warning);line(err,Reports.terminal(warning));}
                if(a.verbose)for(var file:Json.rows(report.get("files")))line(err,Reports.terminal(Json.string(file.get("path")))+": "+file.get("parsed")+" parsed, "+file.get("unparsed")+" unparsed "+Reports.terminal(Json.string(file.get("error"))));
                String mode=!a.format.isEmpty()?a.format:a.output==null?"summary":"html";
                if(a.output!=null){Writer file;try{ManagedFiles.createFile(a.output);file=Files.newBufferedWriter(a.output,StandardCharsets.UTF_8,StandardOpenOption.WRITE);}catch(IOException ex){line(err,Reports.terminal(ex.getMessage()));return 2;}
                    try(file){Reports.write(file,report,mode);}catch(IOException ex){line(err,"Report write failed: "+Reports.terminal(ex.getMessage()));return 1;}Reports.write(out,report,"summary");line(out,"\nReport: "+Reports.terminal(a.output.toString()));}
                else Reports.write(out,report,mode);return Json.bool(report.get("partial"))?1:0;
            }
        }catch(IOException|RuntimeException ex){try{line(err,Reports.terminal(Objects.toString(ex.getMessage(),ex.getClass().getSimpleName())));}catch(IOException ignored){}return 1;}
    }
    static String os(){return System.getProperty("os.name").startsWith("Windows")?"windows":System.getProperty("os.name").startsWith("Mac")?"darwin":"linux";}
    static Path legacyDirectory(){try{var location=Main.class.getProtectionDomain().getCodeSource().getLocation();Path path=Path.of(location.toURI());return (Files.isRegularFile(path)?path.getParent():path).resolve("geoip");}catch(Exception ex){return null;}}
    private static int geoip(String[] args,Writer out,Writer err,Map<String,String> environment,GeoSource source)throws IOException{
        String usage="Usage: webauditJ geoip download|update|status|rollback";
        if(args.length==1&&(args[0].equals("--help")||args[0].equals("-h"))){line(out,usage);return 0;}
        if(args.length!=1||!Set.of("download","update","status","rollback").contains(args[0])){line(err,usage);return 2;}
        Path dir;try{dir=Path.of(GeoPaths.resolve(os(),environment));}catch(IllegalArgumentException ex){line(err,ex.getMessage());return 1;}line(out,"WebAuditJ GeoIP "+args[0]+"\nDirectory: "+Reports.terminal(dir.toString()));
        try{
            if(args[0].equals("status")){try{GeoStore.withCurrent(dir,meta->{status(out,meta);return null;});line(out,"Integrity: OK");return 0;}catch(GeoStore.NotInstalled ex){line(out,"Not installed. Run: webauditJ geoip download");return 0;}catch(IOException ex){line(err,"Integrity: FAILED: "+Reports.terminal(ex.getMessage()));return 1;}}
            GeoSource actual=source!=null?source:new GeoSource(){private DBIPProvider p;private DBIPProvider provider(){if(p==null)p=new DBIPProvider();return p;}public Release latest(String role,long deadline)throws IOException{return provider().latest(role,deadline);}public void fetch(Release release,OutputStream output,long deadline)throws IOException{provider().fetch(release,output,deadline);}};
            var manager=new DatabaseManager(dir,actual);
            if(args[0].equals("rollback")){manager.rollback();line(out,"Previous validated GeoIP generation restored.");return 0;}
            var result=manager.reconcile(args[0].equals("update"));status(out,result.metadata());if(result.changed().isEmpty())line(out,args[0].equals("download")?"Already installed. Use 'webauditJ geoip update' to check for updates.":"No updates available.");else{for(String role:result.changed())line(out,role+": downloaded, validated and activated");line(out,"GeoIP databases ready.");}for(String w:result.warnings())line(err,Reports.terminal(w));return 0;
        }catch(IOException ex){line(err,"GeoIP operation failed: "+Reports.terminal(ex.getMessage()));return 1;}
    }
    private static void status(Writer out,Map<String,Object> meta)throws IOException{
        var current=Json.obj(meta.get("current"));line(out,"Generation: "+Reports.terminal(Json.string(current.get("id")))+"\nLast update check: "+meta.get("last_checked_at"));
        for(var d:Json.rows(current.get("databases"))){line(out,"\n"+d.get("role")+":");for(String field:List.of("provider","version","type","build_time","downloaded_at","size","sha256","url"))line(out,"  "+field+": "+Reports.terminal(Objects.toString(d.get(field),"unknown")));}
        line(out,"\nIP Geolocation by DB-IP — https://db-ip.com — CC BY 4.0");
    }
}
