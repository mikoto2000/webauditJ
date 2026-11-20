package io.github.mikoto2000.webaudit;

import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.type.TypeReference;
import java.io.IOException;
import java.util.*;

final class Json {
    static final JsonMapper MAPPER = JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();
    private Json() {}
    static Map<String,Object> object(String s) { return MAPPER.readValue(s, new TypeReference<LinkedHashMap<String,Object>>() {}); }
    static Object resource(String path) {
        try (var in = Json.class.getResourceAsStream("/" + path)) {
            if (in == null) throw new IllegalStateException("Missing resource " + path);
            return MAPPER.readValue(in, Object.class);
        } catch (IOException e) { throw new IllegalStateException(e); }
    }
    static LinkedHashMap<String,Object> map(Object... pairs) {
        var result = new LinkedHashMap<String,Object>();
        for (int i=0;i<pairs.length;i+=2) result.put((String)pairs[i], pairs[i+1]);
        return result;
    }
    static String string(Object x) { return x == null ? "" : x instanceof String s ? s : MAPPER.writeValueAsString(x); }
    static long number(Object x) { return x instanceof Number n ? n.longValue() : 0; }
    static boolean bool(Object x) { return Boolean.TRUE.equals(x); }
    @SuppressWarnings("unchecked") static Map<String,Object> obj(Object x) { return (Map<String,Object>)x; }
    @SuppressWarnings("unchecked") static List<Map<String,Object>> rows(Object x) { return (List<Map<String,Object>>)x; }
}
