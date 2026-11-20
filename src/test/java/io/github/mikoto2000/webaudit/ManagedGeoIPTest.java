package io.github.mikoto2000.webaudit;
import java.nio.file.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
class ManagedGeoIPTest {
    @TempDir Path dir;
    @Test void opensManagedSnapshotAndKeepsExplicitRolePriority()throws Exception{
        var fake=new DatabaseManagerTest.Fake();var m=new DatabaseManager(dir,fake);m.reconcile(false);var opened=ManagedGeoIP.open("","",dir,null,4);
        try(var g=opened.geo()){assertNotNull(g);assertEquals("2026-11",g.metadata().getFirst().get("version"));String generation=(String)g.metadata().getFirst().get("generation");fake.version="2026-12";m.reconcile(true);assertEquals(generation,g.metadata().getFirst().get("generation"));assertEquals("found",g.lookup("8.8.8.8").get("status"));}
        try(var g=ManagedGeoIP.open(GeoIPTest.db("country"),"",dir,null,4).geo()){assertNull(g.metadata().getFirst().get("generation"));assertEquals("2026-12",g.metadata().get(1).get("version"));}
    }
    @Test void corruptedManagedDataWarnsAndDoesNotFallBackToLegacy()throws Exception{
        Files.writeString(dir.resolve("metadata.json"),"broken");Path legacy=Files.createDirectory(dir.resolve("legacy"));Files.copy(Path.of(GeoIPTest.db("country")),legacy.resolve("country.mmdb"));
        var opened=ManagedGeoIP.open("","",dir,legacy,4);assertNull(opened.geo());assertFalse(opened.warnings().isEmpty());
        try(var g=ManagedGeoIP.open(GeoIPTest.db("country"),GeoIPTest.db("asn"),dir,legacy,4).geo()){assertNotNull(g);}
    }
}
