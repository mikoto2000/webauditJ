package io.github.mikoto2000.webaudit;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
class GeoIPTest {
    @TempDir Path dir;
    static String db(String role)throws Exception{return Path.of(GeoIPTest.class.getResource("/geoip/"+role+".mmdb").toURI()).toString();}
    @Test void readsV4V6AndCachesHitsAndMisses()throws Exception{
        try(var g=GeoIP.open(db("country"),db("asn"),null,2)){
            var hit=g.lookup("8.8.8.8");assertEquals("found",hit.get("status"));assertEquals("ZZ",hit.get("country_code"));assertEquals(64500,Json.number(hit.get("asn")));
            assertEquals(hit,g.lookup("::ffff:8.8.8.8"));assertEquals("found",g.lookup("2606:4700::1").get("status"));
            g.lookup("1.1.1.1");g.lookup("1.1.1.1");assertTrue(Json.number(g.metrics().get("cached_ips"))<=2);assertTrue(Json.number(g.metrics().get("lru_hits"))>=2);
        }
    }
    @Test void distinguishesNonpublicInvalidAbsentAndMissingRecords()throws Exception{
        try(var g=GeoIP.open(db("country"),"",null,2)){
            assertEquals("not_found",g.lookup("1.1.1.1").get("status"));assertEquals("db_not_installed",g.lookup("8.8.8.8").get("asn_status"));
            for(String ip:List.of("127.0.0.1","10.0.0.1","192.0.2.1","100.64.0.1","::1","fe80::1","fc00::1","ff02::1"))assertEquals("non_public",g.lookup(ip).get("status"),ip);
            assertEquals("invalid_ip",g.lookup("example.com").get("status"));assertEquals("invalid_ip",g.lookup("fe80::1%eth0").get("status"));
        }
    }
    @Test void explicitBadDatabaseFailsButMissingAutomaticDatabaseDisables()throws Exception{
        Path bad=dir.resolve("bad.mmdb");Files.writeString(bad,"broken");assertThrows(java.io.IOException.class,()->GeoIP.open(bad.toString(),"",null,2));
        assertNull(GeoIP.open("","",dir,2));assertThrows(java.io.IOException.class,()->GeoIP.open(db("asn"),"",null,2));
    }
}
