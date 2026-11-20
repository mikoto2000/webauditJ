package io.github.mikoto2000.webaudit;

import java.io.*;
import java.nio.file.*;
import java.util.*;

final class GeoCommands {
  private GeoCommands() {}

  private static void line(Writer out, String text) throws IOException {
    out.write(text);
    out.write('\n');
  }

  static int run(
      String[] args, Writer out, Writer err, Map<String, String> environment, GeoSource source)
      throws IOException {
    String usage = "Usage: webauditJ geoip download|update|status|rollback";
    if (args.length == 1 && (args[0].equals("--help") || args[0].equals("-h"))) {
      line(out, usage);
      return 0;
    }
    if (args.length != 1 || !Set.of("download", "update", "status", "rollback").contains(args[0])) {
      line(err, usage);
      return 2;
    }
    Path dir;
    try {
      dir = Path.of(GeoPaths.resolve(Main.os(), environment));
    } catch (IllegalArgumentException ex) {
      line(err, ex.getMessage());
      return 1;
    }
    line(out, "WebAuditJ GeoIP " + args[0] + "\nDirectory: " + Reports.terminal(dir.toString()));
    try {
      if (args[0].equals("status")) {
        try {
          GeoStore.withCurrent(
              dir,
              meta -> {
                status(out, meta);
                return null;
              });
          line(out, "Integrity: OK");
          return 0;
        } catch (GeoStore.NotInstalled ex) {
          line(out, "Not installed. Run: webauditJ geoip download");
          return 0;
        } catch (IOException ex) {
          line(err, "Integrity: FAILED: " + Reports.terminal(ex.getMessage()));
          return 1;
        }
      }
      GeoSource actual =
          source != null
              ? source
              : new GeoSource() {
                private DBIPProvider p;

                private DBIPProvider provider() {
                  if (p == null) p = new DBIPProvider();
                  return p;
                }

                public Release latest(String role, long deadline) throws IOException {
                  return provider().latest(role, deadline);
                }

                public void fetch(Release release, OutputStream output, long deadline)
                    throws IOException {
                  provider().fetch(release, output, deadline);
                }
              };
      var manager = new DatabaseManager(dir, actual);
      if (args[0].equals("rollback")) {
        manager.rollback();
        line(out, "Previous validated GeoIP generation restored.");
        return 0;
      }
      var result = manager.reconcile(args[0].equals("update"));
      status(out, result.metadata());
      if (result.changed().isEmpty())
        line(
            out,
            args[0].equals("download")
                ? "Already installed. Use 'webauditJ geoip update' to check for updates."
                : "No updates available.");
      else {
        for (String role : result.changed())
          line(out, role + ": downloaded, validated and activated");
        line(out, "GeoIP databases ready.");
      }
      for (String w : result.warnings()) line(err, Reports.terminal(w));
      return 0;
    } catch (IOException ex) {
      line(err, "GeoIP operation failed: " + Reports.terminal(ex.getMessage()));
      return 1;
    }
  }

  private static void status(Writer out, Map<String, Object> meta) throws IOException {
    var current = Json.obj(meta.get("current"));
    line(
        out,
        "Generation: "
            + Reports.terminal(Json.string(current.get("id")))
            + "\nLast update check: "
            + meta.get("last_checked_at"));
    for (var d : Json.rows(current.get("databases"))) {
      line(out, "\n" + d.get("role") + ":");
      for (String field :
          List.of(
              "provider",
              "version",
              "type",
              "build_time",
              "downloaded_at",
              "size",
              "sha256",
              "url"))
        line(
            out, "  " + field + ": " + Reports.terminal(Objects.toString(d.get(field), "unknown")));
    }
    line(out, "\nIP Geolocation by DB-IP — https://db-ip.com — CC BY 4.0");
  }
}
