#!/usr/bin/env sh
set -eu

# Run on the target host, for example:
#   RAW_BASE="https://gitea.example.com/fredrik/crowdsec-mcp/raw/branch/main" sh /path/to/install_snort_crowdsec_examples.sh

RAW_BASE="${RAW_BASE:-}"
BRANCH="${BRANCH:-main}"
CONF_DIR="${CONF_DIR:-/srv/appdata/crowdsec/conf}"

if [ -z "$RAW_BASE" ]; then
  echo "RAW_BASE is required." >&2
  echo "Example: RAW_BASE=https://gitea.example.com/<owner>/crowdsec-mcp/raw/branch/${BRANCH}" >&2
  exit 2
fi

case "$CONF_DIR" in
  */conf|*/conf/) ;;
  *)
    echo "Refusing to install outside a CrowdSec conf directory: $CONF_DIR" >&2
    echo "Run from /srv/appdata/crowdsec/conf or set CONF_DIR explicitly." >&2
    exit 2
    ;;
esac

cd "$CONF_DIR"

for required_dir in parsers scenarios notifications; do
  if [ ! -d "$required_dir" ]; then
    echo "Required CrowdSec config directory is missing: ${CONF_DIR}/${required_dir}" >&2
    exit 2
  fi
done

if [ -f "profiles.yaml" ]; then
  PROFILE_FILE="profiles.yaml"
elif [ -f "profiles.yml" ]; then
  PROFILE_FILE="profiles.yml"
else
  echo "Required target CrowdSec profile file is missing: ${CONF_DIR}/profiles.yaml" >&2
  exit 2
fi

fetch() {
  src="$1"
  dst="$2"
  tmp="${dst}.tmp"
  mkdir -p "$(dirname "$dst")"
  curl -fsSL "${RAW_BASE}/${src}" -o "$tmp"
  mv "$tmp" "$dst"
  echo "installed $dst"
}

fetch "examples/parsers/s01-parse/snort-alerts.yaml" \
  "parsers/s01-parse/snort-alerts.yaml"

fetch "examples/crowdsec/scenarios/snort-priority1.yaml" \
  "scenarios/snort-priority1.yaml"
fetch "examples/crowdsec/scenarios/snort-fast-attack-exploit-repeat.yaml" \
  "scenarios/snort-fast-attack-exploit-repeat.yaml"
fetch "examples/crowdsec/scenarios/snort-misc-attack-repeat.yaml" \
  "scenarios/snort-misc-attack-repeat.yaml"
fetch "examples/crowdsec/scenarios/repeat-offender.yaml" \
  "scenarios/repeat-offender.yaml"
fetch "examples/crowdsec/scenarios/snort-db-scan-repeat.yaml" \
  "scenarios/snort-db-scan-repeat.yaml"
fetch "examples/crowdsec/scenarios/snort-sip-repeat.yaml" \
  "scenarios/snort-sip-repeat.yaml"
fetch "examples/crowdsec/scenarios/snort-ssdp-external-repeat.yaml" \
  "scenarios/snort-ssdp-external-repeat.yaml"

fetch "examples/crowdsec/profiles/snort-remediation-profiles.yaml" \
  "snort-remediation-profiles.yaml"

fetch "examples/crowdsec/notifications/http_victoriametrics.yaml" \
  "notifications/http_victoriametrics.yaml.example"

cat <<'EOF'

Next steps on the target host:
  crowdsec -t
  cscli simulation enable local/snort-priority1-repeat
  cscli simulation enable local/snort-fast-attack-exploit-repeat
  cscli simulation enable local/snort-misc-attack-repeat
  cscli simulation enable local/crowdsec-repeat-offender
  cscli simulation enable local/snort-db-scan-repeat
  cscli simulation enable local/snort-sip-repeat
  cscli simulation enable local/snort-ssdp-external-repeat
  systemctl reload crowdsec
  cscli simulation status

The repo profile snippet was saved as snort-remediation-profiles.yaml.
EOF
echo "Merge it into the target ${PROFILE_FILE} manually only if you need Snort-specific duration overrides."
cat <<'EOF'

The VictoriaMetrics notification example was saved as notifications/http_victoriametrics.yaml.example.
Review URL and labels before enabling it as notifications/http_victoriametrics.yaml.
EOF
