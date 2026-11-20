# Go reference fixture generation

Normal Maven tests use the checked-in expected reports and require neither Go nor the original repository. The baseline commit and fixture hashes are recorded in `docs/reference/baseline.json`.

To refresh the fixtures intentionally, use a separate checkout or an archive of Go WebAudit commit `95148ba4e22d9001d34fbb0e4d59f072efd3e95c`, including `go.mod`, `go.sum`, `audit/`, `internal/`, `vendor/`, and `testdata/corpus.json`. Do not run against an unreviewed newer main branch.

Run each generator separately, with the Go repository as its current directory. Both paths below must be absolute:

```sh
go run /path/to/webauditJ/tools/reference/parser.go /path/to/webauditJ/src/test/resources
go run /path/to/webauditJ/tools/reference/detection.go /path/to/webauditJ/src/test/resources
go run /path/to/webauditJ/tools/reference/upstream.go /path/to/webauditJ/src/test/resources
go run /path/to/webauditJ/tools/reference/corpus.go /path/to/webauditJ/src/test/resources
```

The parser generator includes unsupported inputs and records rejection. Detection expectations cover accepted parser inputs. Upstream reports cover each source log separately. Corpus reports reproduce the original evaluator's nonce, timestamp, repeat and interval handling.

The comparison normalizes the execution timestamp, absolute input paths, implementation version, and warning order. Wall-clock incident IDs include the absolute source path, so those IDs are covered separately by the correlation tests. Ordinary incident IDs, observation order, rule IDs, scores, outcome reasons, confidence, counts, evidence and normalization remain part of the report comparison.
