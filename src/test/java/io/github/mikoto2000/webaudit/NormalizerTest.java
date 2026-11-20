package io.github.mikoto2000.webaudit;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class NormalizerTest {
  @Test
  void decodesTwoLevelsAndPreservesOriginal() {
    var n = Normalizer.normalize("/%253Cscript%253E?q=a+b");
    assertEquals("/%253Cscript%253E?q=a+b", n.original());
    assertTrue(n.variants().contains("/<script>?q=a b"));
    assertEquals(
        2, n.steps().stream().filter(s -> s.equals("percent-decode detection variant")).count());
    assertTrue(n.variants().size() <= 7);
  }

  @Test
  void leavesPathPlusAndMalformedPercentIntact() {
    var n = Normalizer.normalize("/a+b/%zz?q=a+b");
    assertTrue(n.variants().contains("/a+b/%zz?q=a b"));
    assertTrue(n.warnings().contains("Invalid percent encoding preserved"));
  }

  @Test
  void handlesLogEscapesAndNonstandardUnicode() {
    var n = Normalizer.normalize("/\\x3cSCRIPT\\x3e/%u003c");
    assertTrue(n.variants().contains("/<script>/%u003c"));
    assertTrue(n.warnings().contains("Nonstandard %u encoding is not decoded"));
  }

  @Test
  void decodedInvalidUtf8IsReportedAndEachBadBytePreservedInOutput() {
    var n = Normalizer.normalize("/%ff%fe");
    assertTrue(n.variants().contains("/\ufffd\ufffd"));
    assertTrue(
        n.warnings().contains("Decoded bytes are not valid UTF-8; no Unicode repair inferred"));
  }

  @Test
  void foldingDoesNotDependOnLocaleOrExpandSharpS() {
    assertTrue(Normalizer.normalize("/İ/ß/\\ADMIN").variants().contains("/i/ß//admin"));
  }
}
