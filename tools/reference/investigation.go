// Run separately against the pinned main-port reference; see README.md.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
	"webaudit/audit"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: investigation.go ABSOLUTE_RESOURCE_DIRECTORY")
	}
	categories := map[string]bool{}
	for _, rule := range audit.Rules() {
		categories[rule.Category] = true
	}
	for _, category := range []string{"404", "auth", "login", "rate", "burst", "paths", "sensitive", "ua", "multi", "WS-url-size", "WS-size", "WS-ip", "WS-errors", "WS-hour", "future-category", "unknown"} {
		categories[category] = true
	}
	keys := []string{}
	for category := range categories { keys = append(keys, category) }
	sort.Strings(keys)
	out := []audit.Investigation{}
	for _, category := range keys {
		c := audit.NewCorrelator(audit.Options{})
		e := audit.Event{IP: "192.0.2.1", Time: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
		c.Add(e, []audit.Rule{{ID: "test", Category: category, Severity: "low"}}, audit.Normalized{})
		out = append(out, c.Finish()[0].Outcome.Investigation...)
	}
	f, err := os.Create(filepath.Join(os.Args[1], "investigation-golden.json"))
	if err != nil { panic(err) }
	defer f.Close()
	if err := json.NewEncoder(f).Encode(out); err != nil { panic(err) }
}
