package io.github.mikoto2000.webaudit;

import java.io.*;

interface GeoSource {
  record Release(String role, String version, String url, String sha1) {}

  Release latest(String role, long deadline) throws IOException;

  void fetch(Release release, OutputStream output, long deadline) throws IOException;
}
