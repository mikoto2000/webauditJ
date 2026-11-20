package io.github.mikoto2000.webaudit;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class GeoPathsTest {
    @Test void usesXdgBeforeOsFallbackAndSeparatesJavaData(){
        assertEquals("/data/webauditJ/geoip",GeoPaths.resolve("linux",Map.of("XDG_DATA_HOME","/data","HOME","/home/me")));
        assertEquals("/home/me/.local/share/webauditJ/geoip",GeoPaths.resolve("darwin",Map.of("XDG_DATA_HOME","relative","HOME","/home/me")));
        assertEquals("D:\\データ\\webauditJ\\geoip",GeoPaths.resolve("windows",Map.of("XDG_DATA_HOME","D:\\データ","LOCALAPPDATA","C:\\Users\\me\\AppData\\Local")));
        assertEquals("C:\\Users\\me\\AppData\\Local\\webauditJ\\geoip",GeoPaths.resolve("windows",Map.of("LOCALAPPDATA","C:\\Users\\me\\AppData\\Local")));
    }
    @Test void acceptsUncShareRootAndRejectsAmbiguousRelativePaths(){
        for(String unc:List.of("\\\\server\\share","//server/share"))assertEquals(unc+"\\webauditJ\\geoip",GeoPaths.resolve("windows",Map.of("XDG_DATA_HOME",unc)));
        assertThrows(IllegalArgumentException.class,()->GeoPaths.resolve("windows",Map.of("XDG_DATA_HOME","C:relative")));
        assertThrows(IllegalArgumentException.class,()->GeoPaths.resolve("linux",Map.of("XDG_DATA_HOME","relative","HOME","")));
    }
}
