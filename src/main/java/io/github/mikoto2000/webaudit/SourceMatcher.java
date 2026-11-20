package io.github.mikoto2000.webaudit;

import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import com.google.re2j.Pattern;
import static io.github.mikoto2000.webaudit.Core.*;

final class SourceMatcher {
    static final List<Map<String,Object>> RULES=Json.rows(Json.resource("upstream/hub.json"));
    static final Map<String,Object> AURA=Json.obj(Json.resource("upstream/aura.json"));
    static final Map<String,Object> SOURCES=Json.obj(Json.resource("upstream/manifest.json"));
    private static final Map<String,List<String>> LISTS=new HashMap<>();
    private static final Map<String,List<Map<String,Object>>> LOOKUPS=new HashMap<>();
    private static final Map<String,Pattern> REGEX=new HashMap<>();
    private static final List<String> FILES=List.of("admin_interfaces.txt","backdoors.txt","bad_user_agents.regex.txt","bad_user_agents.txt","jira_cve_2021-26086.txt","log4j2_cve_2021_44228.txt","path_traversal.txt","sensitive_data.txt","sqli_probe_patterns.txt","technology_probing.json","thinkphp_cve_2018-20062.txt","trendy_cves.txt","trendy_cves_uris.json","xss_probe_patterns.txt");
    static {
        for(String name:FILES) {
            try(var in=SourceMatcher.class.getResourceAsStream("/upstream/data/"+name)) {
                if(in==null)throw new IllegalStateException(name);
                LISTS.put(name,new String(in.readAllBytes(),StandardCharsets.UTF_8).lines().map(String::strip).filter(s->!s.isEmpty()&&!s.startsWith("#")).toList());
            }catch(IOException e){throw new IllegalStateException(e);}
        }
        for(String name:List.of("technology_probing.json","trendy_cves_uris.json"))LOOKUPS.put(name,LISTS.get(name).stream().map(Json::object).toList());
        for(String name:List.of("bad_user_agents.regex.txt","thinkphp_cve_2018-20062.txt"))for(String p:LISTS.get(name))REGEX.put(p,Pattern.compile(p));
        for(var r:Json.rows(AURA.get("signatures")))REGEX.put("(?i)"+r.get("pattern"),Pattern.compile("(?i)"+r.get("pattern")));
    }
    private SourceMatcher() {}
    record View(String full,String req,String args,String lower,String upper,String dir,String frag,String filename,String ext,String qu,String pu,boolean isStatic) {}
    static View view(Event e) {
        String full=field(e,"evt.Meta.http_path"),req=field(e,"evt.Parsed.request"),args=field(e,"evt.Parsed.http_args");
        var m=Pattern.compile("^(.*/)(?:([^/].*?)(\\.[^.]*$|$))?").matcher(req);String dir="",frag="",extension="";
        if(m.find()){dir=s(m.group(1));frag=s(m.group(2));extension=s(m.group(3));}
        String ext=extension.startsWith(".")?extension.substring(1):extension;
        boolean isStatic=!ext.isEmpty()&&"|JPG|CSS|JS|JPEG|PNG|SVG|MAP|ICO|OTF|GIF|MP3|MP4|WOFF|WOFF2|TTF|EOT|WEBP|WAV|GZ|BROTLI|BVR|TS|BMP|AVIF|MJS|TGZ|".contains("|"+upper(ext)+"|");
        return new View(full,req,args,lower(full),upper(full),dir,frag,frag+extension,ext,unescape(full,true),unescape(full,false),isStatic);
    }
    static String sourceUA(Event e){return e.recordedUA!=null?e.recordedUA:s(e.ua);}
    static String sourceReferer(Event e){return e.recordedReferer!=null?e.recordedReferer:s(e.referer);}
    static String field(Event e,String field) {
        String full=e.malformed?s(e.rawRequest):e.target,req=e.sourceRequest!=null?e.sourceRequest:full,args="";
        int q=req.lastIndexOf('?');if(q>=0){args=req.substring(q+1);req=req.substring(0,q);}
        return switch(field){case "evt.Meta.http_path"->full;case "evt.Parsed.request"->req;case "evt.Parsed.http_args"->args;case "evt.Parsed.file_name"->{var v=view(e);yield v.filename();}case "evt.Parsed.http_user_agent"->sourceUA(e);default->"";};
    }
    static String group(Event e,String field){if(field.contains("http_path"))return e.ip+" "+field(e,"evt.Meta.http_path");if(field.contains("target_fqdn")){String host=s(e.host);if(host.matches("^\\[[^]]+]:[0-9]+$"))host=host.substring(1,host.lastIndexOf(']'));else if(host.indexOf(':')==host.lastIndexOf(':')&&host.lastIndexOf(':')>=0)host=host.substring(0,host.lastIndexOf(':'));return e.ip+"/"+host;}return e.ip;}
    static String lower(String s){return Normalizer.lower(s);}static String upper(String s){var b=new StringBuilder();s.codePoints().map(Character::toUpperCase).forEach(b::appendCodePoint);return b.toString();}
    static boolean contains(String a,String b){return a.contains(b);}static boolean starts(String a,String b){return a.startsWith(b);}static boolean ends(String a,String b){return a.endsWith(b);}static int byteLength(String s){return size(s);}
    static boolean re(String p,String s){return REGEX.computeIfAbsent(p,Pattern::compile).matcher(s).find();}
    static boolean matchPatterns(String name,String s){for(String p:LISTS.get(name))if(re(p,s))return true;return false;}
    static boolean listContains(String name,String s,boolean fold){for(String p:LISTS.get(name))if((fold?upper(s):s).contains(fold?upper(p):p))return true;return false;}
    static boolean listExact(String name,String s){return LISTS.get(name).contains(s);}static boolean listSuffix(String name,String s){return LISTS.get(name).stream().anyMatch(s::endsWith);}
    static boolean lookup(String name,String s,String key){if(key.isEmpty())return !lookupTag(name,s).isEmpty();return LOOKUPS.get(name).stream().anyMatch(r->s.contains(Json.string(r.get(key))));}
    static List<Map<String,Object>> rows(String name){return LOOKUPS.get(name);}
    static String lookupTag(String name,String s){String tag="";var rows=LOOKUPS.get(name);for(var row:rows)if("equals".equals(row.get("type"))&&s.equals(row.get("pattern")))tag=Json.string(row.get("tag"));if(!tag.isEmpty())return tag;int pos=-1;for(var row:rows)if("contains".equals(row.get("type"))){int i=s.indexOf(Json.string(row.get("pattern")));if(i>=0&&(pos<0||i<pos)){pos=i;tag=Json.string(row.get("tag"));}}if(!tag.isEmpty())return tag;for(var row:rows)if("regex".equals(row.get("type"))&&re(Json.string(row.get("pattern")),s))return Json.string(row.get("tag"));return "";}
    static String unescape(String s,boolean query){var out=new ByteArrayOutputStream();byte[] b=s.getBytes(StandardCharsets.UTF_8);for(int i=0;i<b.length;i++){int c=b[i]&255;if(c=='%'){if(i+2>=b.length)return s;int a=Character.digit((char)b[i+1],16),z=Character.digit((char)b[i+2],16);if(a<0||z<0)return s;out.write(a*16+z);i+=2;}else out.write(query&&c=='+'?' ':c);}return Utf8.decode(out.toByteArray());}
    static boolean matches(Map<String,Object> r,Event e,View v) {
        if(!e.logType.equals("http_access-log")&&!e.logType.equals("http_error-log"))return false;
        String full=v.full(),req=v.req(),args=v.args(),lower=v.lower(),upper=v.upper(),qu=v.qu(),pu=v.pu(),dir=v.dir(),frag=v.frag(),filename=v.filename(),ext=v.ext();boolean isStatic=v.isStatic();
        int status=e.status==null?0:e.status;String verb=s(e.method);boolean access=e.logType.equals("http_access-log"),denied=status==403||status==404;
        String id=Json.string(r.get("name"));id=id.substring(id.indexOf('/')+1);
        return switch(id) {
            case "apache_log4j2_cve-2021-44228" -> listContains("log4j2_cve_2021_44228.txt", full, true) || listContains("log4j2_cve_2021_44228.txt", sourceUA(e), true) || listContains("log4j2_cve_2021_44228.txt", sourceReferer(e), true);
            case "CVE-2017-9841" -> access && ends(lower, "util/php/eval-stdin.php");
            case "CVE-2019-18935" -> starts(upper(qu), upper("/Telerik.Web.UI.WebResource.axd?type=rau"));
            case "CVE-2022-26134" -> contains(upper(pu), upper("@java.lang.Runtime@getRuntime().exec("));
            case "CVE-2022-35914" -> contains(upper, upper("/vendor/htmlawed/htmlawed/htmLawedTest.php"));
            case "CVE-2022-37042" -> upper(verb).equals("POST") && status >= 400 && status < 410 && (contains(upper, "/SERVICE/EXTENSION/BACKUP/MBOXIMPORT?ACCOUNT-NAME=ADMIN&OW=2&NO-SWITCH=1&APPEND=1") || contains(upper, "/SERVICE/EXTENSION/BACKUP/MBOXIMPORT?ACCOUNT-NAME=ADMIN&ACCOUNT-STATUS=1&OW=CMD"));
            case "fortinet-cve-2022-40684" -> starts(upper, "/API/V2/CMDB/SYSTEM/ADMIN/") && lower(s(e.ua)).equals("report runner");
            case "CVE-2022-41082" -> contains(upper, "/AUTODISCOVER/AUTODISCOVER.JSON") && contains(upper(args), "POWERSHELL");
            case "CVE-2022-41697" -> contains(upper, "/GHOST/API/ADMIN/SESSION") && upper(verb).equals("POST") && status == 404;
            case "CVE-2022-42889" -> contains(upper(pu), "${SCRIPT:JAVASCRIPT:JAVA.LANG.RUNTIME.GETRUNTIME().EXEC(") || contains(upper(pu), "${SCRIPT:JS:JAVA.LANG.RUNTIME.GETRUNTIME().EXEC(") || contains(upper(pu), "${URL:UTF-8:") || contains(upper(pu), "${DNS:ADDRESS|");
            case "CVE-2022-44877" -> upper(verb).equals("POST") && status == 302 && contains(lower, "/index.php") && re("login=.*(\\$|%24)(\\(|%28).*(\\)|%29)", lower(args));
            case "CVE-2022-46169-bf" -> upper(verb).equals("GET") && contains(upper, "/REMOTE_AGENT.PHP") && contains(lower(args), "host_id") && contains(lower(args), "local_data_ids");
            case "CVE-2022-46169-cmd" -> upper(verb).equals("GET") && contains(upper, "/REMOTE_AGENT.PHP") && contains(lower(args), "action=polldata") && re("poller_id=.*(;|%3b)", lower(args));
            case "CVE-2023-22515" -> lower(ext).equals("action") && (contains(lower(dir), "/setup") || lower(frag).equals("server-info"));
            case "CVE-2023-22518" -> upper(verb).equals("POST") && contains(upper, "/JSON/SETUP-RESTORE.ACTION");
            case "CVE-2023-49103" -> contains(lower, "/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/getphpinfo.php");
            case "CVE-2024-0012" -> denied && (re("/php/.*/\\.js\\.map", lower(req)) || re("/index.php/.*\\.js\\.map", lower(req)));
            case "CVE-2024-38475" -> denied && ends(lower(req), "%3f");
            case "CVE-2024-9474" -> denied && verb.equals("POST") && contains(lower(req), "/php/utils/createremoteappwebsession.php/watchtowr.js.map");
            case "f5-big-ip-cve-2020-5902" -> re("/TMUI/LOGIN.JSP/..;/TMUI/[^.]+.JSP\\?(FILENAME|COMMAND|DIRECTORYPATH|TABID)=", upper) || re("/TMUI/LOGIN.JSP/%2E%2E;/TMUI/[^.]+.JSP\\?(FILENAME|COMMAND|DIRECTORYPATH|TABID)=", upper);
            case "fortinet-cve-2018-13379" -> contains(upper, "/REMOTE/FGT_LANG?LANG=/../../../..//////////DEV/CMDB/SSLVPN_WEBSESSION");
            case "grafana-cve-2021-43798" -> re("/PUBLIC/PLUGINS/[^/]+/../[./]+/", upper) || re("/PUBLIC/PLUGINS/[^/]+/%2E%2E/[%2E/]+/", upper);
            case "http-admin-interface-probing" -> denied && listContains("admin_interfaces.txt", lower, false);
            case "http-apiscp-bf" -> access && verb.equals("POST") && status == 200 && starts(full, "/apps/login");
            case "http-backdoors-attempts" -> listExact("backdoors.txt", filename);
            case "http-bad-user-agent" -> matchPatterns("bad_user_agents.regex.txt", sourceUA(e));
            case "http-bf-wordpress_bf" -> access && filename.equals("wp-login.php") && verb.equals("POST") && status == 200;
            case "http-bf-wordpress_bf_xmlrpc" -> access && filename.equals("xmlrpc.php") && verb.equals("POST");
            case "http-crawl-non_statics" -> !isStatic && (verb.equals("GET") || verb.equals("HEAD"));
            case "http-cve-2021-41773" -> contains(upper, "/.%2E/.%2E/") || contains(upper, "/%2E%2E/%2E%2E");
            case "http-cve-2021-42013" -> contains(upper, "/%%32%65%%32%65/");
            case "http-cve-probing" -> denied && lookup("trendy_cves_uris.json", full, "uri");
            case "http-dos-bypass-cache" -> access && !isStatic && re("^[0-9]{7,12}$", args);
            case "http-dos-invalid-http-versions" -> !s(e.protocol).isEmpty() && !Set.of("0.9","1.0","1.1","2.0","3.0").contains(s(e.protocol).replaceFirst("^HTTP/", ""));
            case "http-dos-random-uri" -> access && verb.equals("GET") && !isStatic && upper(frag).equals(frag) && byteLength(frag) == 6 && args.equals("");
            case "http-dos-swithcing-ua" -> true;
            case "http-generic-bf" -> e.authFailure;
            case "http-generic-401-bf" -> access && verb.equals("POST") && status == 401;
            case "http-generic-403-bf" -> access && verb.equals("POST") && status == 403;
            case "http-generic-test" -> full.equals("/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl");
            case "http-open-proxy" -> access && (status == 400 || status == 405) && (verb.equals("CONNECT") || re("^http[s]?://", req));
            case "http-path-traversal-probing" -> listContains("path_traversal.txt", full, false);
            case "http-probing" -> (status == 400 || denied) && !isStatic;
            case "http-sap-interface-probing" -> denied && (lower.equals("/nwa") || Arrays.stream(new String[]{"/sap/bc/gui/sap/its/webgui", "/irj/portal", "/sap/bc/", "/sap/opu/odata/", "/sap/public/bc/", "/sap/public/info", "/sap/public/icf_info", "/sap/admin/publicicp/", "/sap/admin/public/", "/webdynpro/dispatcher/sap.com/tc~sec~ume~wd~umeadmin/umeadminapp", "/sap/hana/xs/admin", "/sap/hana/xs/formlogin", "/irj/go/km/navigation"}).anyMatch(lower::contains));
            case "http-sensitive-files" -> listSuffix("sensitive_data.txt", req);
            case "http-sqli-probbing-detection" -> listContains("sqli_probe_patterns.txt", args, true);
            case "http-technology-probing" -> denied && lookup("technology_probing.json", full, "");
            case "http-wordpress-scan" -> denied && re("(?i)(/wp-.*\\.php|/wp-content/plugins/.*\\.(txt|md))$", lower(req));
            case "http-wordpress_user-enum" -> access && contains(upper(args), "AUTHOR=");
            case "http-wordpress_wpconfig" -> access && contains(filename, "wp-config.php");
            case "http-xss-probbing" -> listContains("xss_probe_patterns.txt", args, true);
            case "jira_cve-2021-26086" -> listContains("jira_cve_2021-26086.txt", full, true);
            case "netgear_rce" -> starts(lower(qu), "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=");
            case "pulse-secure-sslvpn-cve-2019-11510" -> re("/DANA-NA/../DANA/HTML5ACC/GUACAMOLE/../../../../../../../[^?]+\\?/DANA/HTML5ACC/GUACAMOLE/", upper) || re("/DANA-NA/%2E%2E/DANA/HTML5ACC/GUACAMOLE/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/[^?]+\\?/DANA/HTML5ACC/GUACAMOLE/", upper);
            case "spring4shell_cve-2022-22965" -> contains(upper, "CLASS.MODULE.CLASSLOADER.");
            case "thinkphp-cve-2018-20062" -> matchPatterns("thinkphp_cve_2018-20062.txt", lower);
            case "vmware-cve-2022-22954" -> starts(upper(qu), upper("/catalog-portal/ui/oauth/verify?error=&deviceUdid=${\"freemarker.template.utility.Execute\"?new()("));
            case "http-w00tw00t" -> access && (contains(filename, "w00tw00t.at.ISC.SANS.DFind") || lower.equals("/core/skin/login.aspx"));
            case "vmware-vcenter-vmsa-2021-0027" -> re("/ui/vcav-bootstrap/rest/vcav-providers/provider-logo\\?url=(file|http)", full);
            default -> false;
        };
    }
}
