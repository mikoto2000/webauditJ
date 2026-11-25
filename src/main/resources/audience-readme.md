# WebAudit investigation artifacts

Open index.html after copying the entire directory. No server, external library,
LLM, API key or Internet connection is required.

- executive-summary.html: executive decisions, conditional risks and actions.
- technical-report.html: detailed investigation and secondary-prompt generator.
- report.html: established script-free technical entry with links to the new reports.
- technical.html / executive.html: aliases for the audience-specific reports.
- report.json: common analysis, decision support and secondary plan.
- data/investigation-plan.json: trusted task conditions versus untrusted log observations.
- prompts/: all, priority and individual case Markdown requests.
- report-spec.md and templates/: reusable report contract for secondary/tertiary work.
- manifest.json: byte hashes and completeness. An INCOMPLETE marker means generation failed.

The three folder fields name primary artifacts, supplied additional records and
the secondary output destination. They only generate text; they do not inspect
directories, authorize data collection, send logs or start an investigation.
REQ IDs identify source observations, not native application request IDs.
Keep secondary-plan.js, secondary-investigation.js and report.css with the HTML.
Copy may require manual Ctrl+C in local-file browsers; Markdown is always available.
Original logs are unchanged. Review masking and sensitive values before sharing.
Language and applied analysis settings are recorded in report.json/manifest.json.
Reproduction: rerun WebAudit with the recorded inputs, language and effective settings;
verify input and rule hashes. Wall-clock/build metadata can differ between runs.
