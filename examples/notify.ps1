# Explicit invocation: powershell.exe -NoProfile -File examples/notify.ps1
$ErrorActionPreference = 'Stop'
$eventBuffer = [char[]]::new(65537)
$eventLength = 0
while ($eventLength -lt $eventBuffer.Length) {
    $eventRead = [Console]::In.Read($eventBuffer, $eventLength, $eventBuffer.Length - $eventLength)
    if ($eventRead -eq 0) { break }
    $eventLength += $eventRead
}
if ($eventLength -gt 65536) { throw 'event too large' }
$eventData = [string]::new($eventBuffer, 0, $eventLength) | ConvertFrom-Json
if ($eventData.schema_version -ne 1) { throw 'unsupported schema' }
$summary = [ordered]@{
    notification_id = $eventData.notification_id
    incident_id = $eventData.incident_id
    revision = $eventData.revision
    severity = $eventData.severity
    outcome = $eventData.outcome
}
[Console]::Out.WriteLine(($summary | ConvertTo-Json -Compress))
