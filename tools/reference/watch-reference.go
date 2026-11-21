// Run through generate_watch.py inside a temporary directory of the Go source module.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
	"webaudit/audit"
	"webaudit/internal/watch"
)

func main() {
	now := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	type step struct {
		Line   string                `json:"line"`
		At     int                   `json:"at"`
		Events []watch.IncidentEvent `json:"events"`
	}
	type scenario struct {
		Name  string `json:"name"`
		Steps []step `json:"steps"`
	}
	scenarios := []scenario{}
	cases := [][]string{
		{"lifecycle", "/.env", "/.env", "/.env"},
		{"escalation", "/?q=%3Cscript%3E", "/?q=%3Cscript%3E", "/?q=UNION%20SELECT%20password%20FROM%20users"},
		{"behavior", "/one", "/two", "/three", "/four", "/five", "/six", "/seven", "/eight", "/nine", "/ten", "/eleven", "/twelve", "/thirteen", "/fourteen", "/fifteen", "/sixteen", "/seventeen", "/eighteen", "/nineteen", "/twenty"},
		{"normal", "/normal", "/normal", "/normal"},
	}
	for _, c := range cases {
		e := watch.NewEngine(watch.EngineOptions{})
		s := scenario{Name: c[0]}
		for i, target := range c[1:] {
			status := 404
			if c[0] == "normal" || c[0] == "escalation" || c[0] == "lifecycle" && i > 0 {
				status = 200
			}
			line := fmt.Sprintf("198.51.100.1 - - [21/Nov/2026:00:00:%02d +0000] \"GET %s HTTP/1.1\" %d 12 \"-\" \"secret-agent\"", i, target, status)
			v, err := audit.Parse(line, "access.log", int64(i+1), "")
			if err != nil {
				panic(err)
			}
			e.Observe(v, now.Add(time.Duration(i)*time.Second))
			s.Steps = append(s.Steps, step{line, i, e.Flush(now.Add(time.Duration(i) * time.Second))})
		}
		s.Steps = append(s.Steps, step{"", 400, e.Flush(now.Add(400 * time.Second))})
		scenarios = append(scenarios, s)
	}
	if err := json.NewEncoder(os.Stdout).Encode(scenarios); err != nil {
		panic(err)
	}
}
