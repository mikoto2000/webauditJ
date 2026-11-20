# Pinned upstream fixtures

Hub raw logs/config.yaml/parser.assert/scenario.assert are copied unchanged from commit 626d9a38c208ab594ac0078437598257042a59be. MIT notice: ../../upstream/HUB-LICENSE. The files include intentionally malicious request strings as inert test data.

hub-cases.json selects 60 Apache/Nginx scenario cases with HTTP rules supported by this CLI, plus 11 explicitly skipped cases requiring other product parsers. `alerts` is extracted from original assertions, including duplicate alerts for the same IP/rule. `configured` expands all documents in a selected multi-document scenario file. Comparisons filter actual alerts to these installed scenario IDs; production analysis evaluates all enabled rules. Originals are retained to audit extraction.

aura-cases.json records all 31 original URL fixtures and the complete expected tag set obtained by executing the pinned standalone Aura rules.py module (imports inspected: re only). No ES service was started. MIT notice: ../../upstream/AURADFIR-LICENSE.

These are source compatibility fixtures, not ground truth for real attacks. Other HTTP source formats are retained as explicit scope records, not counted as passes.
