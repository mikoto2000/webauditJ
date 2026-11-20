package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"webaudit/audit"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: detection.go ABSOLUTE_RESOURCE_DIRECTORY")
	}
	var rows []map[string]json.RawMessage
	b, err := os.ReadFile(filepath.Join(os.Args[1], "parser-golden.json"))
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(b, &rows); err != nil {
		panic(err)
	}
	if len(rows) == 0 {
		panic("empty parser reference")
	}
	out := []any{}
	for _, r := range rows {
		if r["event"] == nil {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal(r["event"], &e); err != nil {
			panic(err)
		}
		hits, n := audit.Detect(e)
		ids := []string{}
		for _, h := range hits {
			ids = append(ids, h.ID)
		}
		out = append(out, map[string]any{"input": r["input"], "custom": r["custom"], "hits": ids, "normalization": n})
	}
	f, err := os.Create(filepath.Join(os.Args[1], "detection-golden.json"))
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(out); err != nil {
		panic(err)
	}
}
