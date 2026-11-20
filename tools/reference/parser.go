package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"webaudit/audit"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: parser.go ABSOLUTE_RESOURCE_DIRECTORY")
	}
	rows := []any{}
	add := func(s, file string, n int64, custom string) {
		e, err := audit.Parse(s, file, n, custom)
		row := map[string]any{"input": s, "file": file, "line": n, "custom": custom}
		if err != nil {
			row["error"] = err.Error()
		} else {
			row["event"] = e
		}
		rows = append(rows, row)
	}
	root := "audit/testdata/upstream"
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".log") {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			sc := bufio.NewScanner(f)
			var n int64
			for sc.Scan() {
				n++
				if strings.TrimSpace(sc.Text()) != "" {
					add(sc.Text(), "fixture.log", n, "")
				}
			}
			f.Close()
			if err := sc.Err(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
	if len(rows) == 0 {
		panic("empty upstream inputs")
	}
	common := `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET /index?q=1 HTTP/1.1" 200 42`
	for _, s := range []string{common, common + ` "-" "Browser"`, common + ` "-" "-"`, common + ` "203.0.113.5"`, strings.Replace(common, "192.0.2.1", "999.1.1.1", 1), strings.Replace(common, "200 42", "999 42", 1), strings.Replace(common, "GET /index?q=1 HTTP/1.1", `\x16\x03`, 1), `{"remote_addr":"8.8.8.8","time_iso8601":"2026-11-01T00:00:00Z","request":"GET / HTTP/2","status":200}`, `{"remote_addr":"8.8.8.8","remote_addr":"1.1.1.1"}`, "garbage"} {
		add(s, "fixture.log", 1, "")
	}
	add("192.0.2.2 2026-11-01T00:00:00Z /a", "fixture.log", 1, `^(?P<ip>\S+) (?P<time>\S+) (?P<target>\S+)$`)
	f, err := os.Create(filepath.Join(os.Args[1], "parser-golden.json"))
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(rows); err != nil {
		panic(err)
	}
}
