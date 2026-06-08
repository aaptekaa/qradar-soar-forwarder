# QRadar SIEM → IBM SOAR Auto Forwarder

Automatically forwards offenses from **IBM QRadar SIEM** to **IBM QRadar SOAR** as incidents. Runs as a systemd service, polling SIEM every 60 seconds.

## What it does

- Polls QRadar SIEM REST API every 60 seconds for all open offenses
- Creates corresponding incidents in IBM SOAR with description, severity and Source IP
- Prevents duplicates — tracks already-forwarded offense IDs in a JSON state file
- On startup, scans existing SOAR incidents to avoid recreating already-forwarded ones
- Automatically re-authenticates when the SOAR session expires
- Generates HTML incident description with details: time, Source IP, categories, event count

## Architecture

```
IBM QRadar SIEM          IBM QRadar SOAR
(192.168.2.70)    --->   (192.168.2.80)
  /api/siem/offenses       /rest/orgs/{id}/incidents
  /api/siem/source_addresses
```

## Severity Mapping

| QRadar Severity | SOAR Severity |
|-----------------|---------------|
| 9–10            | 6 (Critical)  |
| 7–8             | 5 (High)      |
| 5–6             | 4 (Medium)    |
| 3–4             | 3 (Low)       |
| 1–2             | 2 (Info)      |

## Installation

### Requirements

- Python 3.6+
- Standard library only (urllib, ssl, json, logging)
- RHEL/CentOS/Debian with systemd

### 1. Copy the script

```bash
mkdir -p /opt/soar-ad-enrichment
cp auto_forwarder.py /opt/soar-ad-enrichment/
chmod +x /opt/soar-ad-enrichment/auto_forwarder.py
```

### 2. Configure

Edit the variables at the top of `auto_forwarder.py`:

```python
SOAR_HOST  = '192.168.2.80'      # IBM SOAR IP address
SOAR_EMAIL = 'admin@example.com'  # SOAR login
SOAR_PASS  = 'password'           # SOAR password
SOAR_ORG   = 201                  # SOAR organization ID

SIEM_HOST  = '192.168.2.70'      # QRadar SIEM IP address
SIEM_USER  = 'admin'              # SIEM login
SIEM_PASS  = 'password'           # SIEM password

POLL_INTERVAL = 60                # Poll interval in seconds
MIN_MAGNITUDE = 0                 # Min magnitude to forward (0 = all)

STATE_FILE = '/opt/soar-ad-enrichment/forwarded_offenses.json'
LOG_FILE   = '/opt/soar-ad-enrichment/auto_forwarder.log'
```

### 3. Install systemd service

```bash
cp soar-auto-forwarder.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable soar-auto-forwarder.service
systemctl start soar-auto-forwarder.service
```

### 4. Verify

```bash
systemctl status soar-auto-forwarder.service
tail -f /opt/soar-ad-enrichment/auto_forwarder.log
```

## Log Example

```
2026-06-08 09:49:49 [INFO] Fetched 76 OPEN offenses from QRadar SIEM
2026-06-08 09:50:05 [INFO] Created SOAR incident #2185 for QRadar offense #133
2026-06-08 09:50:09 [INFO] Forwarded 2 new offense(s) to SOAR this cycle
2026-06-08 09:51:13 [INFO] No new offenses to forward
```

## State Files

| File | Purpose |
|------|---------|
| `forwarded_offenses.json` | List of already-forwarded offense IDs |
| `auto_forwarder.log` | Service log |

## MIN_MAGNITUDE Filter

Filter offenses by criticality. QRadar magnitude ranges from 1 to 12.

```python
MIN_MAGNITUDE = 3  # forward only offenses with magnitude >= 3
MIN_MAGNITUDE = 0  # forward all (default)
```

## Stack

- **IBM QRadar SIEM** 7.5.0+
- **IBM QRadar SOAR** 51.x
- **Python** 3.6+
- **RHEL** 8.x / systemd