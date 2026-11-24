package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BundleStatisticsTest {
 @TempDir Path dir;
 static final String JSON="{\"remote_addr\":\"192.0.2.1\",\"time_iso8601\":\"2026-11-01T00:00:00Z\",\"request\":\"GET /healthy HTTP/1.1\",\"status\":200,\"body_bytes_sent\":0,\"request_time\":\"0\",\"http_user_agent\":\"Browser\"}";
 @Test void countsAllAccessesAndKeepsKnownZeroSeparateFromMissing()throws Exception {
  Path input=dir.resolve("access.log");Files.writeString(input,JSON+"\n"+BundleTest.LINE.replace("192.0.2.1","192.0.2.2").replace("00:00:00","00:01:00").replace("GET ","HEAD ").replace("404 0","404 42")+"\n"+BundleTest.LINE.replace("192.0.2.1","192.0.2.2").replace("00:00:00","00:02:00").replace("GET /.env","POST /healthy").replace("404 0","500 84").replace(" \"-\" \"Browser\"","")+"\n");
  var report=Bundle.generate(List.of(input),dir.resolve("report"),new Options(),new BundleOptions());var stats=Json.obj(report.get("statistics"));assertEquals(3,Json.number(stats.get("total_requests")));assertEquals(2,Json.number(stats.get("unique_ips")));
  var bytes=Json.obj(stats.get("response_bytes"));assertEquals(0,((Number)bytes.get("min")).doubleValue());assertEquals(42,((Number)bytes.get("mean")).doubleValue());
  var duration=Json.obj(stats.get("request_duration"));assertEquals(1,Json.number(duration.get("count")));assertEquals(2,Json.number(duration.get("missing")));assertEquals(0,((Number)duration.get("min")).doubleValue());
  for(String dim:List.of("method","status","status_class","ip","host","uri","user_agent"))assertEquals(3,Json.rows(Json.obj(stats.get("dimensions")).get(dim)).stream().mapToLong(row->Json.number(row.get("requests"))).sum(),dim);
  assertEquals(3,Json.rows(stats.get("timeline")).size());assertEquals(3,BundleRequestsTest.csv(dir.resolve("report/statistics/method-summary.csv")).size());
  var limited=new BundleOptions();limited.maxSpoolBytes=1;var lower=Bundle.generate(List.of(input),dir.resolve("limited"),new Options(),limited);assertEquals(3,Json.number(Json.obj(lower.get("statistics")).get("total_requests")));assertFalse(Json.bool(lower.get("evidence_complete")));
 }
 @Test void boundsCardinalityAndAdaptsTimeline()throws Exception {
  Path input=dir.resolve("wide.log");Files.writeString(input,BundleTest.LINE.replace("01/Nov","01/Jan").replace("/.env","/one")+"\n"+BundleTest.LINE.replace("192.0.2.1","192.0.2.2").replace("01/Nov","01/Jun").replace("/.env","/two")+"\n"+BundleTest.LINE.replace("192.0.2.1","192.0.2.3").replace("/.env","/three")+"\n");var options=new Options();options.maxKeys=2;
  var stats=Json.obj(Bundle.generate(List.of(input),dir.resolve("report"),options,new BundleOptions()).get("statistics"));assertTrue(Json.bool(stats.get("truncated")));assertEquals("lower_bound",stats.get("unique_ip_quality"));assertTrue(Json.number(stats.get("timeline_resolution_seconds"))>=86400);
  for(String dim:List.of("ip","uri")){var rows=Json.rows(Json.obj(stats.get("dimensions")).get(dim));assertTrue(rows.size()<=3);assertEquals(3,rows.stream().mapToLong(row->Json.number(row.get("requests"))).sum());}
 }
 @Test void recordsGeoAndInvalidDurationWithoutInventingValues()throws Exception {
  Path input=dir.resolve("geo.log");Files.writeString(input,JSON.replace("192.0.2.1","8.8.8.8").replace("/healthy","/.env").replace("\"request_time\":\"0\"","\"request_time\":\"NaN\"")+"\n");
  try(var geo=GeoIP.open(GeoIPTest.db("country"),GeoIPTest.db("asn"),null,64)){
   var options=new Options();options.geoIP=geo;var stats=Json.obj(Bundle.generate(List.of(input),dir.resolve("report"),options,new BundleOptions()).get("statistics"));assertTrue(Json.bool(stats.get("geoip_enabled")));var country=Json.rows(Json.obj(stats.get("dimensions")).get("country")).getFirst();assertEquals(1,Json.number(country.get("requests")));assertEquals(1,Json.number(country.get("suspicious_requests")));assertEquals(1,Json.number(country.get("unique_ips")));
   var duration=Json.obj(stats.get("request_duration"));assertEquals(0,Json.number(duration.get("count")));assertEquals(1,Json.number(duration.get("invalid")));assertEquals(0,Json.number(duration.get("missing")));assertNull(duration.get("min"));
  }
 }
 @Test void serializesDurationOverflowAsUnavailable()throws Exception {
  Path input=dir.resolve("overflow.log");String row=JSON.replace("\"request_time\":\"0\"","\"request_time\":\"1e308\"");Files.writeString(input,row+"\n"+row+"\n");
  var numeric=Json.obj(Json.obj(Bundle.generate(List.of(input),dir.resolve("report"),new Options(),new BundleOptions()).get("statistics")).get("request_duration"));assertEquals("overflow",numeric.get("sum_quality"));assertNull(numeric.get("sum"));assertNull(numeric.get("mean"));
 }
}
