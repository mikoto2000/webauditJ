# Watch examples

```sh
# Default: start at EOF; restore checkpoint when available.
java -jar target/webauditJ.jar watch /var/log/nginx/access.log

# Replay all input intentionally, then follow. This resets revisions/notifications.
java -jar target/webauditJ.jar watch access.log --reset-state --from beginning --format jsonl

# No checkpoint, two explicit files, out-of-order tolerance of two minutes.
java -jar target/webauditJ.jar watch access.log site_access.log --no-state --allowed-lateness 2m

# Nonrecursive directory selection; error.log excluded by default.
java -jar target/webauditJ.jar watch /var/log/nginx/ --include '*access*.log' --exclude '*private*'

# notify.sh requires Python 3; it prints a safe JSON summary (no external send).
chmod +x examples/notify.sh
java -jar target/webauditJ.jar watch access.log --on-detect ./examples/notify.sh

# Also notify significant updates; repeat --on-detect for a second executable.
java -jar target/webauditJ.jar watch access.log --on-detect ./examples/notify.sh \
  --on-detect-event all --on-detect-severity high --hook-timeout 5s \
  --hook-concurrency 2 --hook-queue-size 64
```

```powershell
java -jar target/webauditJ.jar watch .\access.log --on-detect powershell.exe `
  --on-detect-arg=-NoProfile --on-detect-arg=-File `
  --on-detect-arg=examples/notify.ps1
```

Hook stdout/stderr is drained without retention or display by WebAuditJ. These examples validate and
summarize JSON; adapt them to your explicitly selected notification destination.
Never use eval, Invoke-Expression or command interpolation with event fields.
Executable paths and each argument are separate CLI values; quotes are handled by
the invoking terminal, not by a shell inside WebAudit.

Full schema, checkpoint semantics and limits: [watch guide](../docs/watch.md).
