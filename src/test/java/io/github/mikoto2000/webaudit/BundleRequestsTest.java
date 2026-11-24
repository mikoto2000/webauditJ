package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.apache.commons.csv.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BundleRequestsTest {
 @TempDir Path dir;
 static List<Map<String,String>> csv(Path path)throws IOException {
  try(var reader=Files.newBufferedReader(path);var parser=CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).get().parse(reader)){
   var rows=new ArrayList<Map<String,String>>();for(var row:parser)rows.add(row.toMap());return rows;
  }
 }
 Path mixed()throws IOException {
  Path input=dir.resolve("access.log");var text=new StringBuilder();for(int i=0;i<25;i++)text.append(BundleTest.LINE.replace("/.env","/.env?x=<script>")).append('\n');
  for(int i=0;i<600;i++)text.append(BundleTest.LINE.replace("/.env","/healthy").replace("404 0","200 0")).append('\n');Files.writeString(input,text);return input;
 }
 @Test void preservesFullDistinctObservationsAndSeparatesRelated()throws Exception {
  Path target=dir.resolve("report");var report=Bundle.generate(List.of(mixed()),target,new Options(),new BundleOptions());
  var suspicious=csv(target.resolve("suspicious-requests.csv"));var related=csv(target.resolve("related-requests.csv"));var detections=csv(target.resolve("detections.csv"));
  assertEquals(25,suspicious.size());var ids=new HashSet<String>();
  for(var row:suspicious){assertTrue(ids.add(row.get("request_id")));assertFalse(row.get("source_file_id").isEmpty());assertFalse(row.get("source_line").isEmpty());assertFalse(row.get("finding_ids").isEmpty());assertFalse(row.get("detection_ids").isEmpty());assertFalse(row.containsKey("outcome"));}
  assertTrue(related.size()>=600);assertTrue(related.stream().anyMatch(row->row.get("request_uri").equals("/healthy")));assertTrue(detections.size()>25);assertTrue(Json.bool(report.get("evidence_complete")));
  var evidence=Json.obj(report.get("evidence"));assertEquals(suspicious.size(),Json.number(evidence.get("suspicious_requests")));assertEquals(related.size(),Json.number(evidence.get("related_requests")));
  try(var files=Files.list(target)){assertTrue(files.noneMatch(path->path.getFileName().toString().startsWith(".requests-")));}
 }
 @Test void disclosesSpoolTruncationAndKeepsFullAnalysisCounts()throws Exception {
  Path target=dir.resolve("limited");var options=new BundleOptions();options.maxSpoolBytes=1;
  var report=Bundle.generate(List.of(mixed()),target,new Options(),options);assertEquals(625,Json.number(Json.obj(report.get("analysis")).get("requests")));
  assertFalse(Json.bool(report.get("evidence_complete")));assertFalse(Json.bool(report.get("complete")));assertEquals("partial",report.get("status"));assertTrue(csv(target.resolve("suspicious-requests.csv")).isEmpty());
  try(var files=Files.list(target)){assertTrue(files.noneMatch(path->path.getFileName().toString().startsWith(".requests-")));}
 }
}
