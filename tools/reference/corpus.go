package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"webaudit/audit"
)

type Request struct {
	Target string `json:"target"`
	Status int    `json:"status"`
	Repeat int    `json:"repeat"`
	UA     string `json:"user_agent"`
	Method string `json:"method"`
	Step   int    `json:"step"`
	Bytes  int64  `json:"bytes"`
}
type Case struct {
	ID       string    `json:"id"`
	Requests []Request `json:"requests"`
}

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
	b, readErr := os.ReadFile("testdata/corpus.json")
	if readErr != nil {
		panic(readErr)
	}
	var cases []Case
	if err := json.Unmarshal(b, &cases); err != nil {
		panic(err)
	}
	if len(cases) == 0 {
		panic("empty reference corpus")
	}
	out := []any{}
	temporary, err := os.CreateTemp("", "webauditJ-corpus-*.log")
	if err != nil {
		panic(err)
	}
	file := temporary.Name()
	temporary.Close()
	defer os.Remove(file)
	abs, _ := filepath.Abs(file)
	now := func() time.Time { return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC) }
	for _, c := range cases {
		var lines strings.Builder
		index, elapsed := 0, 0
		for _, q := range c.Requests {
			for i := 0; i < q.Repeat; i++ {
				target := strings.ReplaceAll(q.Target, "{i}", strconv.Itoa(i))
				sep := "?"
				if strings.Contains(target, "?") {
					sep = "&"
				}
				target += sep + "wa_nonce=" + strconv.Itoa(index)
				ts := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(elapsed) * time.Second).Format("02/Jan/2006:15:04:05 -0700")
				fmt.Fprintf(&lines, "192.0.2.1 - - [%s] \"%s %s HTTP/1.1\" %d %d \"-\" \"%s\"\n", ts, q.Method, target, q.Status, q.Bytes, q.UA)
				index++
				elapsed += q.Step
			}
		}
		os.WriteFile(file, []byte(lines.String()), 0600)
		r := audit.Analyze([]string{file}, audit.Options{Now: now})
		data, _ := json.Marshal(r)
		var obj any
		json.Unmarshal(data, &obj)
		out = append(out, map[string]any{"name": c.ID, "lines": strings.Split(strings.TrimSuffix(lines.String(), "\n"), "\n"), "report": clean(obj, abs)})
	}
	f, _ := os.Create(filepath.Join(os.Args[1], "corpus-golden.json"))
	defer f.Close()
	json.NewEncoder(f).Encode(out)
}
