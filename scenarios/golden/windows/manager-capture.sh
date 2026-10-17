#!/bin/sh
# Copy one agent's events out of the Wazuh manager logs (roadmap Phase 0).
#
# Run on the manager after capture.ps1 has finished on the Windows VM.
# Archives need <logall_json>yes</logall_json> in the manager's ossec.conf,
# set before the scenario runs.
#
# Usage: manager-capture.sh AGENT_NAME OUT_DIR
#
# Output: OUT_DIR/archives.json and OUT_DIR/alerts.json, one JSON object per
# line, only events whose agent.name is AGENT_NAME. The time window is applied
# later by `xvm-golden import-manager`, using the manifest timestamps.
# Rotated logs are not read; run this on the same day as the capture.
set -eu

if [ $# -ne 2 ]; then
    echo "usage: $0 AGENT_NAME OUT_DIR" >&2
    exit 2
fi
AGENT=$1
OUT=$2
OSSEC=${OSSEC_DIR:-/var/ossec}
ARCHIVES=$OSSEC/logs/archives/archives.json
ALERTS=$OSSEC/logs/alerts/alerts.json

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
if ! grep -q '<logall_json>yes</logall_json>' "$OSSEC/etc/ossec.conf"; then
    echo "logall_json is not enabled in $OSSEC/etc/ossec.conf" >&2
    exit 1
fi
for f in "$ARCHIVES" "$ALERTS"; do
    [ -r "$f" ] || { echo "cannot read $f" >&2; exit 1; }
done

mkdir -p "$OUT"
jq -c --arg a "$AGENT" 'select(.agent.name == $a)' "$ARCHIVES" > "$OUT/archives.json"
jq -c --arg a "$AGENT" 'select(.agent.name == $a)' "$ALERTS" > "$OUT/alerts.json"

echo "archives: $(wc -l < "$OUT/archives.json") events"
echo "alerts:   $(wc -l < "$OUT/alerts.json") alerts"
