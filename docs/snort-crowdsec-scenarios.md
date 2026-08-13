# Snort-Derived CrowdSec Scenarios

This note contains operator-reviewed example CrowdSec scenarios for repeated Snort alert patterns.

These files are examples for a CrowdSec deployment, not runtime behavior inside `crowdsec-ops-mcp`. The MCP remains CrowdSec-only and does not install, mutate, or reload CrowdSec configuration.

## Evidence Behind The Examples

The scenarios were drafted from a reviewed Snort alert export with these dominant patterns:

- SSDP amplification noise: high volume, local WAN-to-gateway pattern.
- Database service scans: repeated alerts across `1433`, `1521`, `3306`, and `5432`.
- SIPVicious or SIP scans: repeated alerts around `UDP/5060`.
- ET known compromised or hostile host traffic: repeated `25000xx` SIDs.
- Priority 1 alerts: low-volume but high-severity Snort detections.
- Fast attack or exploit bursts: five or more relevant alerts from one source within one to two minutes.

Do not copy real local public IPs or gateway IPs into a public repository. Keep local topology values in private CrowdSec parser metadata, private acquisition configuration, or a local-only scenario copy.

## Parser Assumptions

The scenarios assume the Snort parser in `examples/parsers/s01-parse/snort-alerts.yaml` or an equivalent local parser produces:

| Field | Meaning |
| --- | --- |
| `evt.Line.Labels.type` | `snort`, usually from acquisition labels |
| `evt.Meta.log_type` | `snort_alert` |
| `evt.Meta.source_ip` | source IP to group and remediate |
| `evt.Meta.local_wan_ip` | optional private/local metadata for the public WAN IP |
| `evt.Meta.wan_gateway_ip` | optional private/local metadata for the WAN gateway |
| `evt.Meta.target_ip` | destination IP |
| `evt.Meta.target_port` | destination port as a string |
| `evt.Parsed.sid` | Snort SID as a string |
| `evt.Parsed.snort_message` | Snort alert message |
| `evt.Parsed.classification` | Snort classification |
| `evt.Parsed.priority` | Snort priority as a string |

If your local parser uses different field names, update the `filter` expressions before testing.

The scenario examples use `evt.Line.Labels.type == 'snort'` as the first eligibility check because that is how the parser is selected. `evt.Meta.log_type == 'snort_alert'` is still useful metadata for downstream reasoning, but it is not required by these example scenario filters.

## Whitelist Assumptions

These scenarios assume the deployment already has local infrastructure allowlisting or whitelisting in CrowdSec, especially for RFC1918 networks and trusted internal systems.

That keeps the scenario filters readable and avoids repeating broad private-network exclusions in every rule. If the local whitelist is not active, either enable it first or add explicit `IpInRange(...)` exclusions to the scenario copy before rollout.

## Scenario Files

- `examples/crowdsec/scenarios/snort-db-scan-repeat.yaml`
- `examples/crowdsec/scenarios/snort-sip-repeat.yaml`
- `examples/crowdsec/scenarios/snort-misc-attack-repeat.yaml`
- `examples/crowdsec/scenarios/snort-priority1.yaml`
- `examples/crowdsec/scenarios/snort-fast-attack-exploit-repeat.yaml`
- `examples/crowdsec/scenarios/repeat-offender.yaml`
- `examples/crowdsec/scenarios/snort-ssdp-external-repeat.yaml`

The SSDP scenario is intentionally `remediation: false`. The reviewed evidence was dominated by a local WAN-to-gateway SSDP pattern, which should be treated as tuning/noise until topology confirms otherwise.

The `local/snort-misc-attack-repeat` scenario intentionally matches the Snort `Misc Attack` classification instead of a fixed SID list. This keeps it useful when ET adds or changes known-compromised and hostile-host SIDs. Keep it in simulation first because the classification is broader than the originally observed `25000xx` SID set.

The `local/snort-fast-attack-exploit-repeat` scenario catches short bursts of high-risk Snort alerts. Its `capacity: 4` and `leakspeed: "2m"` mean the fifth distinct matching alert from the same source within roughly two minutes triggers the bucket. Keep it in simulation first; remove the `distinct` line in a local copy only if raw repeated volume should count even when the same SID and target repeat.

## Profile Snippet

This repo does not contain your deployment's `profiles.yaml`. It contains only `examples/crowdsec/profiles/snort-remediation-profiles.yaml`, an optional snippet with profile entries:

- `local/snort-priority1-repeat`: `12h` ban.
- other remediating `local/snort-*` scenarios: `4h` ban.

Your target machine's `profiles.yaml` already has early profiles for scenarios containing `exploit`, `scan`, or `cve`, with a `168h` ban and `on_success: break`. That means the Snort examples can be remediated without adding this profile snippet, provided the scenario labels keep behavior values such as `generic:scan`, `sip:scan`, or `generic:exploit`.

With that profile chain:

- `local/snort-priority1-repeat` should match `critical-attacks` because its behavior is `generic:exploit`.
- `local/snort-fast-attack-exploit-repeat` should match `critical-attacks` because its behavior is `http:exploit`.
- `local/snort-misc-attack-repeat` should match `critical-attacks` because its behavior is `generic:scan`.
- `local/snort-db-scan-repeat` should match `critical-attacks` because its behavior is `generic:scan`.
- `local/snort-sip-repeat` should match `critical-attacks` because its behavior is `sip:scan`.
- `local/snort-ssdp-external-repeat` should not remediate because it has `remediation: false`.

Only use the profile snippet if you want Snort-specific durations that differ from the existing `critical-attacks` profile. If you do use it, insert it before broader remediation profiles and include your normal notification targets.

For your current profile setup, the practical recommendation is to install the parser and scenarios, enable simulation, and leave the target `profiles.yaml` unchanged until the simulation evidence is clean.

## Recommended Rollout

1. Install only the scenarios you intend to test.
2. Validate syntax with `crowdsec -t`.
3. Enable simulation for every new scenario first.
4. Reload CrowdSec.
5. Watch `crowdsec.log`, `cscli alerts list`, and `cscli decisions list`.
6. Run for at least `7d` before promotion.

## Pull From Gitea On The Target Host

From a target host where CrowdSec configuration is mounted at `/srv/appdata/crowdsec/conf`, use the install script with a Gitea raw-file base URL.

The script defaults `CONF_DIR` to `/srv/appdata/crowdsec/conf`, changes into that directory, and fails if the expected target CrowdSec config paths are missing: `parsers/`, `scenarios/`, `notifications/`, and a profile file. It prefers the target `profiles.yaml` and also accepts `profiles.yml`.

```bash
curl -fsSL "https://gitea.example.com/<owner>/crowdsec-mcp/raw/branch/main/scripts/install_snort_crowdsec_examples.sh" \
  | RAW_BASE="https://gitea.example.com/<owner>/crowdsec-mcp/raw/branch/main" sh
```

Replace `https://gitea.example.com/<owner>/crowdsec-mcp` with the real Gitea repository URL.

The script installs:

- `parsers/s01-parse/snort-alerts.yaml`
- the example scenario files under `scenarios/`
- `snort-remediation-profiles.yaml` as a repo-provided profile snippet for manual review
- `notifications/http_victoriametrics.yaml.example` as a notification example for manual review

It does not overwrite the target `profiles.yaml`. With the profile chain shown above, that is the recommended behavior. The optional repo snippet is saved beside it as `snort-remediation-profiles.yaml` for manual review only.

The VictoriaMetrics notification file is a CrowdSec notification example, not an MCP integration. Review the URL and labels, then rename it to `notifications/http_victoriametrics.yaml` only if you want CrowdSec itself to send those notifications.

If your CrowdSec config root is different:

```bash
curl -fsSL "https://gitea.example.com/<owner>/crowdsec-mcp/raw/branch/main/scripts/install_snort_crowdsec_examples.sh" \
  | CONF_DIR="/path/to/crowdsec/conf" RAW_BASE="https://gitea.example.com/<owner>/crowdsec-mcp/raw/branch/main" sh
```

Example install commands:

```bash
sudo install -m 0644 examples/parsers/s01-parse/snort-alerts.yaml /etc/crowdsec/parsers/s01-parse/snort-alerts.yaml
sudo install -m 0644 examples/crowdsec/scenarios/snort-db-scan-repeat.yaml /etc/crowdsec/scenarios/snort-db-scan-repeat.yaml
sudo install -m 0644 examples/crowdsec/scenarios/snort-sip-repeat.yaml /etc/crowdsec/scenarios/snort-sip-repeat.yaml
sudo install -m 0644 examples/crowdsec/scenarios/snort-misc-attack-repeat.yaml /etc/crowdsec/scenarios/snort-misc-attack-repeat.yaml
sudo install -m 0644 examples/crowdsec/scenarios/snort-priority1.yaml /etc/crowdsec/scenarios/snort-priority1.yaml
sudo install -m 0644 examples/crowdsec/scenarios/snort-fast-attack-exploit-repeat.yaml /etc/crowdsec/scenarios/snort-fast-attack-exploit-repeat.yaml
sudo install -m 0644 examples/crowdsec/scenarios/snort-ssdp-external-repeat.yaml /etc/crowdsec/scenarios/snort-ssdp-external-repeat.yaml
sudo crowdsec -t
```

If you want custom decision durations, merge the repo snippet manually into the target `/etc/crowdsec/profiles.yaml` before broader catch-all profiles, and add your standard notifications such as `http_telegram`, `http_victoriametrics`, and `email_default` if you want those notifications for Snort decisions.

Suggested simulation set:

```text
local/snort-db-scan-repeat
local/snort-sip-repeat
local/snort-misc-attack-repeat
local/snort-priority1-repeat
local/snort-fast-attack-exploit-repeat
local/snort-ssdp-external-repeat
```

Enable simulation:

```bash
sudo cscli simulation enable local/snort-db-scan-repeat
sudo cscli simulation enable local/snort-sip-repeat
sudo cscli simulation enable local/snort-misc-attack-repeat
sudo cscli simulation enable local/snort-priority1-repeat
sudo cscli simulation enable local/snort-fast-attack-exploit-repeat
sudo cscli simulation enable local/snort-ssdp-external-repeat
sudo systemctl reload crowdsec
sudo cscli simulation status
```

Watch simulation results:

```bash
sudo tail -f /var/log/crowdsec.log
sudo cscli alerts list
sudo cscli decisions list
```

In simulation, CrowdSec still records alerts and simulated decisions, but remediation should not be enforced by bouncers.

Promote one scenario out of simulation only after the simulation period is clean:

```bash
sudo cscli simulation disable local/snort-misc-attack-repeat
sudo systemctl reload crowdsec
sudo cscli simulation status
```

Roll back into simulation if it is too noisy:

```bash
sudo cscli simulation enable local/snort-misc-attack-repeat
sudo systemctl reload crowdsec
```

Promotion criteria:

- repeated true-positive source IPs
- no trusted scanners or providers caught
- no local WAN, gateway, or internal resolver noise
- bouncers enforcing decisions correctly

Tuning criteria:

- repeated local infrastructure sources
- repeated cloud or search-engine sources that should be allowed
- high duplicate ingestion
- scenario fires from one Snort event repeated by logging infrastructure rather than independent events
