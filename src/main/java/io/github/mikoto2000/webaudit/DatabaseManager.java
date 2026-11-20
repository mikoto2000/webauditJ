package io.github.mikoto2000.webaudit;
import java.io.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import java.nio.channels.FileChannel;
import java.nio.channels.Channels;
import java.util.zip.GZIPInputStream;
final class DatabaseManager {
    final Path dir;GeoSource source;Clock clock=Clock.systemUTC();long maxDatabase=256L<<20;
    interface Fault {void at(String point)throws IOException;}
    Fault fault=point->{};
    record Result(Map<String,Object> metadata,List<String> changed,List<String> warnings){}
    DatabaseManager(Path dir,GeoSource source){this.dir=dir.toAbsolutePath().normalize();this.source=source;}
    private static void check(long deadline)throws IOException{if(Thread.currentThread().isInterrupted()||System.nanoTime()>deadline)throw new IOException("GeoIP operation interrupted or timed out");}
    Result reconcile(boolean update)throws IOException{
        GeoStore.directories(dir);GeoStore.safe(dir);long deadline=System.nanoTime()+300_000_000_000L;var warnings=new ArrayList<String>();
        try(var lock=GeoStore.lock(dir)){
            Map<String,Object> old=null;try{old=GeoStore.read(dir);}catch(GeoStore.NotInstalled ignored){}
            if(old!=null)GeoStore.validate(dir,Json.obj(old.get("current")));cleanup(old,warnings);if(old!=null&&!update)return new Result(old,List.of(),warnings);
            if(old==null&&!update)for(String role:List.of("country","asn"))if(Files.exists(dir.resolve(role+".mmdb"),LinkOption.NOFOLLOW_LINKS))throw new IOException("unmanaged "+role+".mmdb already exists; use explicit DB paths or 'geoip update' to install a managed generation");
            var releases=new ArrayList<GeoSource.Release>();var changed=new ArrayList<String>();List<Map<String,Object>> oldDB=old==null?List.of():Json.rows(Json.obj(old.get("current")).get("databases"));
            for(int i=0;i<2;i++){check(deadline);String role=i==0?"country":"asn";var r=source.latest(role,deadline);DBIPProvider.allowed(r.url());if(!r.role().equals(role)||r.version().isEmpty())throw new IOException("invalid "+role+" release");if(old!=null&&r.version().compareTo(Json.string(oldDB.get(i).get("version")))<0)throw new IOException("official "+role+" release is older than installed; refusing downgrade");releases.add(r);if(old==null||!r.version().equals(oldDB.get(i).get("version"))||!r.sha1().equals(oldDB.get(i).get("source_sha1")))changed.add(role);}
            if(changed.isEmpty()){var next=new LinkedHashMap<>(old);next.put("last_checked_at",Times.instant(clock.instant()));publish(next,deadline);return new Result(next,changed,warnings);}
            Path stage=Files.createTempDirectory(dir,".staging-");String id="gen-"+stage.getFileName().toString().substring(".staging-".length());Path finalPath=dir.resolve("versions").resolve(id);boolean published=false;
            try{
                var next=Json.map("format",1,"last_checked_at",Times.instant(clock.instant()));var databases=new ArrayList<Map<String,Object>>();next.put("current",Json.map("id",id,"databases",databases));if(old!=null)next.put("previous",old.get("current"));
                for(int i=0;i<2;i++){check(deadline);String role=i==0?"country":"asn";Path path=stage.resolve(role+".mmdb");Map<String,Object> d;
                    if(changed.contains(role))d=download(releases.get(i),path,deadline);
                    else{d=new LinkedHashMap<>(oldDB.get(i));copy(dir.resolve((String)d.get("file")),path);}
                    d.put("file","versions/"+id+"/"+role+".mmdb");databases.add(d);fault.at("after-"+role);
                }
                GeoStore.directories(dir.resolve("versions"));Files.move(stage,finalPath,StandardCopyOption.ATOMIC_MOVE);fault.at("after-generation");GeoStore.validate(dir,Json.obj(next.get("current")));check(deadline);publish(next,deadline);published=true;cleanup(next,warnings);return new Result(next,changed,warnings);
            }finally{try{GeoStore.deleteTree(dir,stage);}catch(IOException ex){warnings.add("Could not remove interrupted GeoIP staging: "+ex.getMessage());}if(!published)try{GeoStore.deleteTree(dir,finalPath);}catch(IOException ex){warnings.add("Old GeoIP generation is in use; cleanup deferred: "+ex.getMessage());}}
        }catch(RuntimeException ex){throw new IOException("GeoIP operation failed",ex);}
    }
    private Map<String,Object> download(GeoSource.Release release,Path path,long deadline)throws IOException{
        Path packed=Files.createTempFile(path.getParent(),"compressed-","");
        try{
            try(var out=Files.newOutputStream(packed)){source.fetch(release,out,deadline);}check(deadline);if(Files.size(packed)>64L<<20)throw new IOException("GeoIP compressed download exceeds size limit");
            GeoStore.createFile(path);try(var in=new GZIPInputStream(Files.newInputStream(packed),65536);var channel=FileChannel.open(path,StandardOpenOption.WRITE);var out=Channels.newOutputStream(channel)){
                long total=0;byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1){check(deadline);total+=n;if(total>maxDatabase)throw new IOException("decompressed database exceeds size limit");out.write(b,0,n);}out.flush();channel.force(true);
            }
            var d=GeoStore.inspect(path,release.role());if(!release.sha1().equals(d.get("source_sha1")))throw new IOException("official decompressed MMDB SHA1 mismatch");d.put("version",release.version());d.put("url",release.url());d.put("downloaded_at",Times.instant(clock.instant()));return d;
        }finally{Files.deleteIfExists(packed);}
    }
    private static void copy(Path from,Path to)throws IOException{GeoStore.createFile(to);try(var in=Files.newInputStream(from);var channel=FileChannel.open(to,StandardOpenOption.WRITE);var out=Channels.newOutputStream(channel)){in.transferTo(out);out.flush();channel.force(true);}}
    private void publish(Map<String,Object> meta,long deadline)throws IOException{
        check(deadline);fault.at("manifest-write");Path temp=Files.createTempFile(dir,".manifest-","");
        try{byte[] data=Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(meta);try(var channel=FileChannel.open(temp,StandardOpenOption.WRITE)){java.nio.ByteBuffer bytes=java.nio.ByteBuffer.wrap(data);while(bytes.hasRemaining())channel.write(bytes);channel.force(true);}fault.at("manifest-replace");check(deadline);Files.move(temp,dir.resolve("metadata.json"),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
            try(var directory=FileChannel.open(dir,StandardOpenOption.READ)){directory.force(true);}catch(IOException|UnsupportedOperationException ignored){}
        }finally{Files.deleteIfExists(temp);}
    }
    void rollback()throws IOException{
        GeoStore.safe(dir);try(var lock=GeoStore.lock(dir)){var meta=GeoStore.read(dir);if(meta.get("previous")==null)throw new IOException("no previous GeoIP generation is available");GeoStore.validate(dir,Json.obj(meta.get("previous")));Object current=meta.get("current");meta.put("current",meta.get("previous"));meta.put("previous",current);publish(meta,System.nanoTime()+300_000_000_000L);}catch(RuntimeException ex){throw new IOException("GeoIP rollback failed",ex);}
    }
    private void cleanup(Map<String,Object> meta,List<String> warnings){
        try(var paths=Files.list(dir)){for(Path p:paths.toList()){String name=p.getFileName().toString();if(name.startsWith(".staging-")||name.startsWith(".manifest-"))try{GeoStore.deleteTree(dir,p);}catch(IOException ex){warnings.add("Could not remove interrupted GeoIP staging: "+ex.getMessage());}}}catch(IOException ignored){}
        var keep=new HashSet<String>();if(meta!=null){keep.add(Json.string(Json.obj(meta.get("current")).get("id")));if(meta.get("previous")!=null)keep.add(Json.string(Json.obj(meta.get("previous")).get("id")));}
        Path versions=dir.resolve("versions");if(Files.isDirectory(versions))try(var paths=Files.list(versions)){for(Path p:paths.toList()){String name=p.getFileName().toString();if(GeoStore.GENERATION.matcher(name).matches()&&!keep.contains(name))try{GeoStore.deleteTree(dir,p);}catch(IOException ex){warnings.add("Old GeoIP generation is in use; cleanup deferred: "+ex.getMessage());}}}catch(IOException ignored){}
    }
}
