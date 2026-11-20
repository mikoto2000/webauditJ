package io.github.mikoto2000.webaudit;
import java.util.Map;
import java.util.ArrayDeque;
import com.google.re2j.Pattern;
final class GeoPaths {
    private GeoPaths(){}
    private static final Pattern WINDOWS_ABSOLUTE=Pattern.compile("^(?:[a-zA-Z]:[\\\\/]|[\\\\/]{2}[^\\\\/]+[\\\\/][^\\\\/]+(?:[\\\\/]|$))");
    static String resolve(String os,Map<String,String> environment){
        boolean windows=os.equals("windows");String x=environment.getOrDefault("XDG_DATA_HOME","");
        if(absolute(x,windows))return join(x,windows);
        if(windows){x=environment.getOrDefault("LOCALAPPDATA","");if(absolute(x,true))return join(x,true);throw new IllegalArgumentException("GeoIP directory: set absolute XDG_DATA_HOME or LOCALAPPDATA");}
        x=environment.getOrDefault("HOME","");if(absolute(x,false))return join(x+"/.local/share",false);throw new IllegalArgumentException("GeoIP directory: set absolute XDG_DATA_HOME or HOME");
    }
    private static boolean absolute(String s,boolean windows){return !s.isEmpty()&&(windows?WINDOWS_ABSOLUTE.matcher(s).find():s.startsWith("/"));}
    private static String join(String base,boolean windows){if(windows)return base.replaceAll("[\\\\/]+$","")+"\\webauditJ\\geoip";return cleanUnix(base+"/webauditJ/geoip");}
    private static String cleanUnix(String input){var parts=new ArrayDeque<String>();for(String p:input.split("/")){if(p.isEmpty()||p.equals("."))continue;if(p.equals("..")){if(!parts.isEmpty())parts.removeLast();}else parts.add(p);}return "/"+String.join("/",parts);}
}
