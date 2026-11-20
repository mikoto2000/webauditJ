package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
	"webaudit/audit"
)

func clean(v any, path string) any {
	switch x := v.(type) {
	case string:
		return strings.ReplaceAll(x, path, "fixture.log")
	case []any:
		for i, y := range x {
			x[i] = clean(y, path)
		}
	case map[string]any:
		for k, y := range x {
			x[k] = clean(y, path)
		}
	}
	return v
}
func main() {
	if len(os.Args) != 2 {
		panic("usage: upstream.go ABSOLUTE_RESOURCE_DIRECTORY")
	}
	out := []any{}
	err := filepath.WalkDir("audit/testdata/upstream", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".log") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		r := audit.Analyze([]string{path}, audit.Options{Now: func() time.Time { return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC) }})
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		var obj any
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		out = append(out, map[string]any{"name": filepath.ToSlash(path), "lines": strings.Split(strings.TrimSuffix(string(b), "\n"), "\n"), "report": clean(obj, abs)})
		return nil
	})
	if err != nil {
		panic(err)
	}
	if len(out) == 0 {
		panic("empty upstream inputs")
	}
	f, err := os.Create(filepath.Join(os.Args[1], "upstream-golden.json"))
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(out); err != nil {
		panic(err)
	}
}
