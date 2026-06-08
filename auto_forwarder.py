#!/usr/bin/env python3
"""
QRadar SOAR - Auto Offense Forwarder Service
Polls QRadar SIEM for new OPEN offenses and automatically creates SOAR incidents.
Runs every 60 seconds. Tracks forwarded offense IDs to avoid duplicates.
"""

import json
import re
import time
import logging
import urllib.request
import urllib.parse
import ssl
import base64
from datetime import datetime, timezone

# --- Config ---
SOAR_HOST     = '192.168.2.80'
SOAR_EMAIL    = 'administrator@test.com'
SOAR_PASS     = 'AdminPass'
SOAR_ORG      = 201

SIEM_HOST     = '192.168.2.70'
SIEM_USER     = 'admin'
SIEM_PASS     = 'AdminPass'

POLL_INTERVAL = 60   # seconds
STATE_FILE    = '/opt/soar-ad-enrichment/forwarded_offenses.json'
LOG_FILE      = '/opt/soar-ad-enrichment/auto_forwarder.log'

# Only forward offenses with magnitude >= this threshold (0 = forward all)
MIN_MAGNITUDE = 0

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


# ═══════════════════════════════════════════════════════════════════════════
# SOAR API client
# ═══════════════════════════════════════════════════════════════════════════

class SOARClient:
    def __init__(self):
        self.base = 'https://' + SOAR_HOST
        self.csrf = None
        self.cookie_jar = urllib.request.HTTPCookieProcessor()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=SSL_CTX),
            self.cookie_jar
        )
        self._login()

    def _login(self):
        body = json.dumps({'email': SOAR_EMAIL, 'password': SOAR_PASS}).encode()
        req = urllib.request.Request(
            self.base + '/rest/session',
            data=body,
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
            method='POST'
        )
        with self.opener.open(req, timeout=15) as r:
            resp = json.loads(r.read())
        self.csrf = resp.get('csrf_token')
        log.info('SOAR login OK, csrf=%s', self.csrf)

    def _req(self, method, path, body=None, _retry=True):
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        if self.csrf:
            headers['X-sess-id'] = self.csrf
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=15) as r:
                return json.loads(r.read())
        except urllib.request.HTTPError as e:
            if e.code in (401, 404) and _retry:
                log.warning('SOAR session expired (%s), re-logging in...', e.code)
                try:
                    # Reset cookie jar and re-login
                    self.cookie_jar = urllib.request.HTTPCookieProcessor()
                    self.opener = urllib.request.build_opener(
                        urllib.request.HTTPSHandler(context=SSL_CTX),
                        self.cookie_jar
                    )
                    self._login()
                    return self._req(method, path, body, _retry=False)
                except Exception as re_e:
                    log.error('Re-login failed: %s', re_e)
            log.error('SOAR %s %s failed: %s', method, path, e)
            return {}
        except Exception as e:
            log.error('SOAR %s %s failed: %s', method, path, e)
            return {}

    def get_incidents(self):
        return self._req('GET', '/rest/orgs/%d/incidents' % SOAR_ORG) or []

    def create_incident(self, body):
        return self._req('POST', '/rest/orgs/%d/incidents' % SOAR_ORG, body)

    def add_note(self, inc_id, text):
        return self._req('POST',
            '/rest/orgs/%d/incidents/%d/comments' % (SOAR_ORG, inc_id),
            {'text': {'format': 'html', 'content': text}}
        )


# ═══════════════════════════════════════════════════════════════════════════
# QRadar SIEM API client
# ═══════════════════════════════════════════════════════════════════════════

class SIEMClient:
    def __init__(self):
        creds = base64.b64encode(('%s:%s' % (SIEM_USER, SIEM_PASS)).encode()).decode()
        self.headers = {
            'Authorization': 'Basic ' + creds,
            'Accept': 'application/json',
            'Version': '16.0',
        }
        self.base = 'https://' + SIEM_HOST

    def _get(self, path):
        req = urllib.request.Request(self.base + path, headers=self.headers)
        try:
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as r:
                return json.loads(r.read())
        except Exception as e:
            log.error('SIEM GET %s failed: %s', path, e)
            return None

    def get_open_offenses(self):
        fields = ('id,description,offense_source,severity,'
                  'magnitude,start_time,last_updated_time,'
                  'source_address_ids,event_count,categories')
        url = ('/api/siem/offenses?status=OPEN&fields=' +
               urllib.parse.quote(fields))
        result = self._get(url)
        return result if isinstance(result, list) else []

    def get_source_ips(self, ids):
        ips = []
        for sid in (ids or [])[:3]:
            data = self._get('/api/siem/source_addresses/%d' % sid)
            if data and data.get('source_ip'):
                ips.append(data['source_ip'])
        return ips


# ═══════════════════════════════════════════════════════════════════════════
# State helpers
# ═══════════════════════════════════════════════════════════════════════════

def load_state():
    try:
        with open(STATE_FILE) as f:
            return set(str(x) for x in json.load(f))
    except Exception:
        return set()


def save_state(forwarded):
    with open(STATE_FILE, 'w') as f:
        json.dump(sorted(forwarded), f)


def get_existing_qradar_ids(soar):
    ids = set()
    incidents = soar.get_incidents()
    if not isinstance(incidents, list):
        return ids
    for inc in incidents:
        qid = (inc.get('properties') or {}).get('qradar_id')
        if qid:
            ids.add(str(qid))
    return ids


# ═══════════════════════════════════════════════════════════════════════════
# Incident builder
# ═══════════════════════════════════════════════════════════════════════════

SEVERITY_MAP = {10: 6, 9: 6, 8: 5, 7: 5, 6: 4, 5: 4, 4: 3, 3: 3, 2: 3, 1: 2}


def build_incident_name(offense):
    oid  = offense.get('id', '')
    desc = offense.get('description', 'Unknown').strip().replace('\n', ' ')
    # Collapse multiple spaces
    desc = re.sub(r'\s+', ' ', desc)
    src  = offense.get('offense_source', '')
    if len(desc) > 120:
        desc = desc[:120] + '...'
    if src:
        return 'QRadar ID %s , %s - %s' % (oid, desc, src)
    return 'QRadar ID %s , %s' % (oid, desc)


def build_description_html(offense, src_ips):
    ts = datetime.fromtimestamp(
        offense.get('start_time', 0) / 1000.0, tz=timezone.utc
    ).strftime('%Y-%m-%d %H:%M:%S UTC')
    cats = ', '.join(offense.get('categories') or []) or 'N/A'
    ips  = ', '.join(src_ips) if src_ips else 'N/A'
    mag  = offense.get('magnitude', 'N/A')
    sev  = offense.get('severity', 'N/A')
    evt  = offense.get('event_count', 'N/A')
    return (
        '<div style="font-family:sans-serif;">'
        '<h3>QRadar Offense #%s</h3>'
        '<table style="border-collapse:collapse;">'
        '<tr><td style="padding:3px 10px;width:160px;"><b>Start Time</b></td><td>%s</td></tr>'
        '<tr style="background:#f5f5f5;"><td style="padding:3px 10px;"><b>Source</b></td><td>%s</td></tr>'
        '<tr><td style="padding:3px 10px;"><b>Source IP(s)</b></td><td>%s</td></tr>'
        '<tr style="background:#f5f5f5;"><td style="padding:3px 10px;"><b>Severity</b></td><td>%s</td></tr>'
        '<tr><td style="padding:3px 10px;"><b>Magnitude</b></td><td>%s</td></tr>'
        '<tr style="background:#f5f5f5;"><td style="padding:3px 10px;"><b>Events</b></td><td>%s</td></tr>'
        '<tr><td style="padding:3px 10px;"><b>Categories</b></td><td>%s</td></tr>'
        '</table>'
        '<p style="color:#888;font-size:11px;margin-top:8px;">'
        'Auto-forwarded from QRadar SIEM at %s</p>'
        '</div>'
    ) % (
        offense.get('id'),
        ts,
        offense.get('offense_source', 'N/A'),
        ips, sev, mag, evt, cats,
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    )


def forward_offense(soar, siem, offense):
    oid      = offense['id']
    src_ips  = siem.get_source_ips(offense.get('source_address_ids') or [])
    qsev     = offense.get('severity', 5)
    soar_sev = SEVERITY_MAP.get(int(qsev), 4)
    name     = build_incident_name(offense)
    desc_html = build_description_html(offense, src_ips)
    start_ms  = offense.get('start_time', int(time.time() * 1000))

    inc_body = {
        'name':            name,
        'description':     {'format': 'html', 'content': desc_html},
        'discovered_date': start_ms,
        'plan_status':     'A',
        'severity_code':   soar_sev,
        'properties': {
            'qradar_id':   str(oid),
            'ad_source_ip': ', '.join(src_ips) if src_ips else '',
        },
    }

    result = soar.create_incident(inc_body)
    inc_id = result.get('id')
    if not inc_id:
        log.error('Failed to create SOAR incident for offense %s: %s', oid, result)
        return None

    log.info('Created SOAR incident #%s for QRadar offense #%s: %s',
             inc_id, oid, name[:80])
    return inc_id


# ═══════════════════════════════════════════════════════════════════════════
# Main loop
# ═══════════════════════════════════════════════════════════════════════════

def main():
    log.info('=== SOAR Auto Offense Forwarder starting ===')
    soar = SOARClient()
    siem = SIEMClient()

    log.info('Scanning existing SOAR incidents for already-forwarded offenses...')
    existing  = get_existing_qradar_ids(soar)
    forwarded = load_state()
    forwarded |= existing
    save_state(forwarded)
    log.info('Already-forwarded offense IDs: %d', len(forwarded))

    while True:
        try:
            offenses = siem.get_open_offenses()
            log.info('Fetched %d OPEN offenses from QRadar SIEM', len(offenses))
            new_count = 0
            for offense in offenses:
                oid = str(offense.get('id', ''))
                if not oid or oid in forwarded:
                    continue
                mag = offense.get('magnitude', 0)
                if MIN_MAGNITUDE > 0 and mag < MIN_MAGNITUDE:
                    log.debug('Skipping offense %s (magnitude %s < %s)',
                              oid, mag, MIN_MAGNITUDE)
                    forwarded.add(oid)
                    continue
                try:
                    inc_id = forward_offense(soar, siem, offense)
                    if inc_id:
                        new_count += 1
                except Exception as e:
                    log.error('Error forwarding offense %s: %s', oid, e)
                forwarded.add(oid)
                # Save state incrementally so restarts don't reprocess
                save_state(forwarded)
            if new_count:
                log.info('Forwarded %d new offense(s) to SOAR this cycle', new_count)
            else:
                log.info('No new offenses to forward')
        except Exception as e:
            log.error('Main loop error: %s', e)
            try:
                soar = SOARClient()
            except Exception:
                pass

        time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    main()
