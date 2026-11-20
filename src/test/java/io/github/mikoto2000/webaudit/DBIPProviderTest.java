package io.github.mikoto2000.webaudit;
import java.io.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class DBIPProviderTest {
    static final String URL="https://download.db-ip.com/free/dbip-country-lite-2026-11.mmdb.gz";
    static String page(String url,String month){return "<dl><dt>Format</dt><dd>MMDB</dd><dt>Release</dt><dd>"+month+"</dd><dt>SHA1SUM</dt><dd>"+"a".repeat(40)+"</dd></dl><a href='"+url+"'>download</a>";}
    @Test void acceptsOnlyOfficialReleaseAndFindsPublishedMonth()throws Exception{
        DBIPProvider.allowed(URL);var r=DBIPProvider.parse(page(URL,"November 2026"),"country");assertEquals("2026-11",r.version());assertEquals("a".repeat(40),r.sha1());
        for(String bad:new String[]{URL.replace("https:","http:"),URL+"?a=1",URL.replace("download.db-ip.com","evil.example"),"https://user@download.db-ip.com/free/dbip-country-lite-2026-11.mmdb.gz",URL.replace(".com/",".com:443/")})assertThrows(IOException.class,()->DBIPProvider.allowed(bad));
        assertThrows(IOException.class,()->DBIPProvider.parse(page(URL,"October 2026"),"country"));assertThrows(IOException.class,()->DBIPProvider.parse("changed","country"));
    }
    @Test void refusesUnsafeRedirectAndHttpErrorsWithoutRealNetwork(){
        var redirect=new DBIPProvider((uri,timeout,out,limit)->new DBIPProvider.Response(302,"https://evil.example/db"));
        assertThrows(IOException.class,()->redirect.latest("country",System.nanoTime()+60_000_000_000L));
        var error=new DBIPProvider((uri,timeout,out,limit)->new DBIPProvider.Response(500,null));assertThrows(IOException.class,()->error.latest("country",System.nanoTime()+60_000_000_000L));
    }
}
