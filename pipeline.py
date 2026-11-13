from __future__ import annotations
import argparse, csv, hashlib, hmac, json, os, re, sqlite3, sys
from collections import Counter, defaultdict
from datetime import date, datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any

IST = timezone(timedelta(hours=5, minutes=30))
SCHEMA_DIR = Path(__file__).parent / 'schemas'
DB_DEFAULT = Path(__file__).parent / 'pipeline.sqlite3'
KEY_DEFAULT = Path(__file__).parent / '.pii.key'


def load_schemas():
    return {p.stem: json.loads(p.read_text(encoding='utf-8')) for p in sorted(SCHEMA_DIR.glob('*.json'))}


def norm_header(s: str) -> str:
    return re.sub(r'[_\s]+', ' ', (s or '').strip().lower())


def normalize_phone(value: str) -> str:
    digits = re.sub(r'\D', '', value or '')
    if len(digits) == 12 and digits.startswith('91'):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith('0'):
        digits = digits[1:]
    if len(digits) != 10 or digits[0] not in '6789':
        raise ValueError('invalid_phone')
    return '+91' + digits


def parse_date(value: str) -> str:
    s = value.strip()
    for fmt in ('%Y-%m-%d', '%d/%m/%Y', '%d-%m-%Y', '%d-%b-%Y'):
        try:
            return datetime.strptime(s, fmt).date().isoformat()
        except ValueError:
            pass
    raise ValueError('invalid_date')


def parse_decimal(value: str) -> str:
    s = value.strip()
    s = re.sub(r'^(?:₹|Rs\.?|INR)\s*', '', s, flags=re.I)
    s = s.replace(',', '')
    try:
        d = Decimal(s)
    except InvalidOperation:
        raise ValueError('invalid_decimal')
    if not d.is_finite() or d < 0:
        raise ValueError('invalid_decimal')
    return str(d.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP))


def parse_value(field: dict, raw: str | None):
    if raw is None or not str(raw).strip():
        return None
    s = str(raw).strip()
    typ = field['type']
    if typ == 'string': return s
    if typ == 'phone': return normalize_phone(s)
    if typ == 'date': return parse_date(s)
    if typ == 'decimal': return parse_decimal(s)
    if typ == 'enum':
        vals = {v.lower(): v.lower() for v in field.get('values', [])}
        if s.lower() not in vals: raise ValueError('invalid_enum')
        return vals[s.lower()]
    raise ValueError(f'unsupported_type:{typ}')


class Crypto:
    """Authenticated encryption for PII and keyed HMAC for deterministic lookup."""
    def __init__(self, path: Path):
        try:
            from cryptography.fernet import Fernet
        except ImportError as e:
            raise SystemExit('Missing dependency. Run: pip install -r requirements.txt') from e
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(Fernet.generate_key())
            try: os.chmod(path, 0o600)
            except OSError: pass
        self._fernet = Fernet(path.read_bytes().strip())
        self._hmac_key = hashlib.sha256(path.read_bytes().strip() + b'phone-index-v1').digest()
    def encrypt(self, s: str | None):
        return self._fernet.encrypt(s.encode()).decode() if s is not None else None
    def decrypt(self, s: str | None):
        return self._fernet.decrypt(s.encode()).decode() if s is not None else None
    def phone_hash(self, phone: str):
        return hmac.new(self._hmac_key, phone.encode(), hashlib.sha256).hexdigest()


def connect(db_path: Path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    con.execute('PRAGMA journal_mode=WAL')
    con.executescript('''
    CREATE TABLE IF NOT EXISTS leads (
      id INTEGER PRIMARY KEY, workflow_id TEXT NOT NULL, phone_hash TEXT NOT NULL,
      phone_cipher TEXT NOT NULL, customer_name_cipher TEXT NOT NULL,
      external_ref TEXT NOT NULL, batch_id TEXT NOT NULL, fields_json TEXT NOT NULL,
      UNIQUE(workflow_id, phone_hash)
    );
    CREATE INDEX IF NOT EXISTS idx_leads_ref ON leads(workflow_id, external_ref);
    CREATE TABLE IF NOT EXISTS rejections (
      workflow_id TEXT NOT NULL, batch_id TEXT NOT NULL, row_number INTEGER NOT NULL,
      reason TEXT NOT NULL, PRIMARY KEY(workflow_id,batch_id,row_number)
    );
    CREATE TABLE IF NOT EXISTS ledger (
      event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, workflow_id TEXT NOT NULL,
      call_id TEXT, occurred_at TEXT NOT NULL, occurred_ist TEXT NOT NULL,
      phone_hash TEXT, lead_id INTEGER REFERENCES leads(id), payload_json TEXT NOT NULL,
      raw_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_ledger_call ON ledger(workflow_id,call_id);
    CREATE INDEX IF NOT EXISTS idx_ledger_lead ON ledger(lead_id,event_type);
    CREATE TABLE IF NOT EXISTS orphan_events (
      event_id TEXT PRIMARY KEY REFERENCES ledger(event_id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS seen_event_ids (event_id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS unknown_disposition_events (event_id TEXT PRIMARY KEY REFERENCES ledger(event_id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS quality (
      key TEXT PRIMARY KEY, value INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS ingested_drops (
      drop_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, ingested_at TEXT NOT NULL
    );
    ''')
    return con


def qadd(con, key, amount=1):
    con.execute('INSERT INTO quality(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=value+excluded.value',(key,amount))


def quality_dict(con):
    q = {r['key']: r['value'] for r in con.execute('SELECT key,value FROM quality')}
    reasons = dict(sorted(Counter({r['reason']: 0 for r in con.execute('SELECT reason FROM rejections')}).items()))
    for r in con.execute('SELECT reason,COUNT(*) n FROM rejections GROUP BY reason'):
        reasons[r['reason']] = r['n']
    # Keep the common rejection reasons present even if zero; include any others observed.
    for k in ('invalid_phone','missing_required:customer_name','missing_required:phone'):
        reasons.setdefault(k, 0)
    reasons = dict(sorted(reasons.items()))
    return {
      'lead_rows_total': q.get('lead_rows_total',0), 'lead_rows_rejected': q.get('lead_rows_rejected',0),
      'rejections_by_reason': reasons, 'duplicate_lead_rows_merged': q.get('duplicate_lead_rows_merged',0),
      'field_warnings': q.get('field_warnings',0), 'events_total': q.get('events_total',0),
      'malformed_events': q.get('malformed_events',0), 'duplicate_events_dropped': q.get('duplicate_events_dropped',0),
      'orphan_events': con.execute('SELECT COUNT(*) FROM orphan_events').fetchone()[0],
      'unknown_disposition_events': con.execute('SELECT COUNT(*) FROM unknown_disposition_events').fetchone()[0]
    }


def fingerprint_drop(root: Path):
    h = hashlib.sha256()
    for p in sorted(x for x in root.rglob('*') if x.is_file()):
        h.update(str(p.relative_to(root)).encode()); h.update(b'\0'); h.update(p.read_bytes())
    return h.hexdigest()


def ingest_leads(con, root: Path, schemas, crypto: Crypto):
    for wf_dir in sorted((root/'leads').glob('*')) if (root/'leads').exists() else []:
        wf = wf_dir.name
        if wf not in schemas: continue
        schema = schemas[wf]
        fields = schema['fields']
        aliases = {}
        for f in fields:
            for name in [f['name'], *f.get('aliases',[])]: aliases[norm_header(name)] = f['name']
        for csv_path in sorted(wf_dir.glob('*.csv'), key=lambda p:p.name):
            batch = csv_path.stem
            with csv_path.open(newline='', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                header_map = {}
                for col in reader.fieldnames or []:
                    target = aliases.get(norm_header(col))
                    if target and target not in header_map: header_map[target] = col
                nonblank_row = 0
                for row in reader:
                    if not any(str(v or '').strip() for v in row.values()): continue
                    nonblank_row += 1
                    qadd(con,'lead_rows_total')
                    parsed, warnings, reason = {}, 0, None
                    for field in fields:
                        name = field['name']; raw = row.get(header_map.get(name,'')) if name in header_map else None
                        try: val = parse_value(field, raw)
                        except ValueError as e:
                            val = None
                            if field['type'] == 'phone' and raw is not None and str(raw).strip():
                                reason = 'invalid_phone'
                            else: warnings += 1
                        parsed[name] = val
                        if reason: break
                        if field.get('required') and val is None:
                            reason = f'missing_required:{name}'; break
                    if reason:
                        con.execute('INSERT OR IGNORE INTO rejections VALUES(?,?,?,?)',(wf,batch,nonblank_row,reason))
                        qadd(con,'lead_rows_rejected')
                        continue
                    qadd(con,'field_warnings',warnings)
                    phone = parsed['phone']; phash = crypto.phone_hash(phone)
                    ref_field = next(x['name'] for x in fields if x.get('reference'))
                    ref = parsed[ref_field]
                    existing = con.execute('SELECT id,fields_json FROM leads WHERE workflow_id=? AND phone_hash=?',(wf,phash)).fetchone()
                    # PII fields are excluded from fields_json; encrypted separately.
                    safe = {k:v for k,v in parsed.items() if not next((x for x in fields if x['name']==k),{}).get('pii')}
                    if existing:
                        old = json.loads(existing['fields_json'])
                        old.update({k:v for k,v in safe.items() if v is not None})
                        # name is PII and follows the same non-null last-write-wins rule.
                        name_cipher = crypto.encrypt(parsed['customer_name']) if parsed['customer_name'] is not None else None
                        phone_cipher = crypto.encrypt(phone)
                        con.execute('UPDATE leads SET phone_cipher=?, customer_name_cipher=COALESCE(?,customer_name_cipher), external_ref=?, fields_json=? WHERE id=?',
                                    (phone_cipher,name_cipher,old.get(ref_field) or ref,json.dumps(old,separators=(',',':')),existing['id']))
                        qadd(con,'duplicate_lead_rows_merged')
                    else:
                        con.execute('INSERT INTO leads(workflow_id,phone_hash,phone_cipher,customer_name_cipher,external_ref,batch_id,fields_json) VALUES(?,?,?,?,?,?,?)',
                                    (wf,phash,crypto.encrypt(phone),crypto.encrypt(parsed['customer_name']),ref,batch,json.dumps(safe,separators=(',',':'))))

    # Apply schema defaults only after the rows in this ingestion have merged.
    for lead in con.execute('SELECT id,workflow_id,fields_json FROM leads').fetchall():
        data=json.loads(lead['fields_json']); changed=False
        for field in schemas[lead['workflow_id']]['fields']:
            if field.get('default') is not None and data.get(field['name']) is None:
                data[field['name']]=field['default']; changed=True
        if changed:
            con.execute('UPDATE leads SET fields_json=? WHERE id=?',(json.dumps(data,separators=(',',':')),lead['id']))


def classify_bucket(calls, dispositions, workflow_id):
    if not calls: return 'yet_to_reach_out'
    if any(dispositions.get((workflow_id,c.get('code')),{}).get('is_terminal',False) for c in calls): return 'completed'
    if all(c.get('telephony_failed',False) for c in calls): return 'in_progress_telephony_failed'
    return 'in_progress_dialed'


def parse_timestamp(s: str):
    if not isinstance(s,str) or not s.strip(): raise ValueError('bad timestamp')
    raw=s.strip()
    if raw.endswith('Z'): dt=datetime.fromisoformat(raw[:-1]+'+00:00')
    else: dt=datetime.fromisoformat(raw)
    if dt.tzinfo is None: dt=dt.replace(tzinfo=IST)
    return dt, dt.astimezone(IST)


def load_dispositions(path: Path):
    result={}
    with path.open(newline='',encoding='utf-8-sig') as f:
        for r in csv.DictReader(f):
            result[(r['workflow_id'],r['code'])]={'is_terminal':r['is_terminal'].strip().lower()=='true','is_success':r['is_success'].strip().lower()=='true'}
    return result


def reconcile_events(con, dispositions):
    # First link all phone-bearing events. This also allows override events to precede their call's phone event.
    rows=con.execute('SELECT event_id,workflow_id,call_id,phone_hash,event_type FROM ledger WHERE lead_id IS NULL AND phone_hash IS NOT NULL').fetchall()
    for r in rows:
        lead=con.execute('SELECT id FROM leads WHERE workflow_id=? AND phone_hash=?',(r['workflow_id'],r['phone_hash'])).fetchone()
        if lead: con.execute('UPDATE ledger SET lead_id=? WHERE event_id=?',(lead['id'],r['event_id']))
    # Resolve no-phone overrides from any already-linked event for the same call.
    rows=con.execute("SELECT event_id,workflow_id,call_id FROM ledger WHERE lead_id IS NULL AND event_type='disposition.override'").fetchall()
    for r in rows:
        lead=con.execute('SELECT lead_id FROM ledger WHERE workflow_id=? AND call_id=? AND lead_id IS NOT NULL LIMIT 1',(r['workflow_id'],r['call_id'])).fetchone()
        if lead: con.execute('UPDATE ledger SET lead_id=? WHERE event_id=?',(lead['lead_id'],r['event_id']))
    # Quarantine is a derived set; unresolved events can become linked in a later drop.
    con.execute('DELETE FROM orphan_events')
    con.execute('INSERT INTO orphan_events(event_id) SELECT event_id FROM ledger WHERE lead_id IS NULL')
    con.execute('DELETE FROM unknown_disposition_events')
    for r in con.execute("SELECT event_id,workflow_id,payload_json FROM ledger WHERE lead_id IS NOT NULL AND event_type LIKE 'disposition.%'").fetchall():
        code=json.loads(r['payload_json']).get('disposition_code')
        if (r['workflow_id'],code) not in dispositions:
            con.execute('INSERT INTO unknown_disposition_events(event_id) VALUES(?)',(r['event_id'],))


def ingest_events(con, root: Path, dispositions):
    events_dir=root/'events'
    if not events_dir.exists(): return
    for path in sorted(events_dir.glob('*.jsonl'),key=lambda p:p.name):
        with path.open(encoding='utf-8') as f:
            for line in f:
                if not line.strip(): continue
                qadd(con,'events_total')
                try:
                    e=json.loads(line)
                    if not isinstance(e,dict) or not e.get('event_id'): raise ValueError('missing event_id')
                except Exception:
                    qadd(con,'malformed_events'); continue
                if con.execute('SELECT 1 FROM seen_event_ids WHERE event_id=?',(str(e['event_id']),)).fetchone():
                    qadd(con,'duplicate_events_dropped'); continue
                con.execute('INSERT INTO seen_event_ids(event_id) VALUES(?)',(str(e['event_id']),))
                wf=e.get('workflow_id'); et=e.get('event_type'); call_id=e.get('call_id')
                if not wf or not et:
                    qadd(con,'malformed_events'); continue
                payload=e.get('payload') or {}
                try:
                    original, ist=parse_timestamp(e.get('occurred_at'))
                except Exception:
                    qadd(con,'malformed_events'); continue
                phone_hash=None
                if et!='disposition.override':
                    raw_phone=e.get('phone')
                    if raw_phone:
                        try: phone_hash=CRYPTO.phone_hash(normalize_phone(str(raw_phone)))
                        except ValueError: phone_hash=None
                con.execute('INSERT INTO ledger(event_id,event_type,workflow_id,call_id,occurred_at,occurred_ist,phone_hash,lead_id,payload_json,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?)',
                            (str(e['event_id']),et,wf,call_id,original.isoformat(),ist.isoformat(),phone_hash,None,json.dumps(payload,separators=(',',':')),json.dumps({k:v for k,v in e.items() if k!='phone'},separators=(',',':'))))
    reconcile_events(con, dispositions)


def select_effective_disposition(rows, dispositions):
    # Unknown catalogue codes are ignored before selecting the latest effective event.
    known=[]
    for r in rows:
        code=json.loads(r['payload_json']).get('disposition_code')
        if (r['workflow_id'],code) in dispositions:
            known.append(r)
    if not known: return None
    overrides=[r for r in known if r['event_type']=='disposition.override']
    chosen=max(overrides or known,key=lambda r:(parse_timestamp(r['occurred_at'])[0],r['event_id']))
    return json.loads(chosen['payload_json']).get('disposition_code')


def effective_dispositions(con, dispositions):
    by_call=defaultdict(list)
    for r in con.execute('SELECT * FROM ledger WHERE lead_id IS NOT NULL AND event_type IN (\'disposition.set\',\'disposition.override\')'):
        by_call[(r['lead_id'],r['workflow_id'],r['call_id'])].append(r)
    result={}
    for key, rows in by_call.items():
        code=select_effective_disposition(rows,dispositions)
        if code is not None: result[key]=code
    return result


def build_reports(con, out: Path, schemas, dispositions):
    out.mkdir(parents=True,exist_ok=True)
    eff=effective_dispositions(con,dispositions)
    # Calls are initiated events only; all event facts are associated by lead + call id.
    calls=defaultdict(dict)
    for r in con.execute("SELECT * FROM ledger WHERE lead_id IS NOT NULL"):
        key=(r['lead_id'],r['workflow_id'],r['call_id'])
        calls[key].setdefault('events',[]).append(r)
        if r['event_type']=='call.initiated': calls[key]['initiated']=r
    calls={k:v for k,v in calls.items() if 'initiated' in v}
    lead_calls=defaultdict(list); daily=defaultdict(list)
    for (lead_id,wf,cid), c in calls.items():
        init=c['initiated']; connected=any(x['event_type']=='call.connected' for x in c['events'])
        code=eff.get((lead_id,wf,cid)); facts=dispositions.get((wf,code),{})
        info={'lead_id':lead_id,'workflow_id':wf,'call_id':cid,'initiated':init['occurred_ist'],'connected':connected,'code':code,'success':facts.get('is_success',False),'events':c['events']}
        lead_calls[lead_id].append(info); daily[(wf,init['occurred_ist'][:10])].append(info)
    batch_rows=[]
    lead_rows=[]
    for lead in con.execute('SELECT * FROM leads ORDER BY workflow_id,batch_id,external_ref'):
        wf=lead['workflow_id']; schema=schemas[wf]
        ref_field=next(f['name'] for f in schema['fields'] if f.get('reference'))
        fields=json.loads(lead['fields_json'])
        ref=fields.get(ref_field) or lead['external_ref']
        cs=lead_calls.get(lead['id'],[])
        bucket_calls=[{**c,'telephony_failed':any(e['event_type']=='call.telephony_failed' for e in c['events'])} for c in cs]
        bucket=classify_bucket(bucket_calls,dispositions,wf)
        connected=sum(c['connected'] for c in cs)
        last=max((c['initiated'] for c in cs),default=None)
        disp_calls=[c for c in cs if c['code']]
        current=max(disp_calls,key=lambda c:c['initiated'])['code'] if disp_calls else ''
        phone=CRYPTO.decrypt(lead['phone_cipher'])
        masked='+91******'+phone[-4:]
        lead_rows.append([wf,ref,lead['batch_id'],masked,bucket,len(cs),connected,last or '',current,str(any(c['success'] for c in cs)).lower()])
        batch_rows.append((wf,lead['batch_id'],bucket))
    batch_counts=defaultdict(Counter)
    for wf,batch,bucket in batch_rows:
        batch_counts[(wf,batch)]['total_leads']+=1; batch_counts[(wf,batch)][bucket]+=1
    with (out/'batch_summary.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f,lineterminator='\n'); w.writerow(['workflow_id','batch_id','total_leads','yet_to_reach_out','in_progress_telephony_failed','in_progress_dialed','completed'])
        for (wf,batch),c in sorted(batch_counts.items()): w.writerow([wf,batch,c['total_leads'],c['yet_to_reach_out'],c['in_progress_telephony_failed'],c['in_progress_dialed'],c['completed']])
    with (out/'daily_overview.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f,lineterminator='\n'); w.writerow(['workflow_id','date','total_calls','connected_calls','connectivity_rate','success_leads'])
        for (wf,day),cs in sorted(daily.items()):
            success=len({c['lead_id'] for c in cs if c['success']})
            connected=sum(c['connected'] for c in cs)
            w.writerow([wf,day,len(cs),connected,f'{connected/len(cs):.4f}',success])
    with (out/'lead_report.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f,lineterminator='\n'); w.writerow(['workflow_id','external_ref','batch_id','phone_masked','bucket','total_calls','connected_calls','last_call_at','current_disposition','ever_success'])
        w.writerows(sorted(lead_rows,key=lambda r:(r[0],r[1])))
    with (out/'rejections.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f,lineterminator='\n'); w.writerow(['workflow_id','batch_id','row_number','reason'])
        for r in con.execute('SELECT workflow_id,batch_id,row_number,reason FROM rejections ORDER BY workflow_id,batch_id,row_number'): w.writerow(list(r))
    (out/'data_quality.json').write_text(json.dumps(quality_dict(con),indent=2)+'\n',encoding='utf-8')

# Global set by main to keep ingestion helper signatures small.
CRYPTO=None

def main():
    global CRYPTO
    ap=argparse.ArgumentParser(description='Interaction ledger and reporting pipeline')
    ap.add_argument('--db',default=str(DB_DEFAULT),help='SQLite database path')
    ap.add_argument('--key',default=str(KEY_DEFAULT),help='PII encryption key path; back it up securely')
    sub=ap.add_subparsers(dest='command',required=True)
    ing=sub.add_parser('ingest'); ing.add_argument('drop',help='Path to one drop directory')
    rep=sub.add_parser('report'); rep.add_argument('--out',required=True)
    args=ap.parse_args(); db=connect(Path(args.db)); CRYPTO=Crypto(Path(args.key))
    schemas=load_schemas(); dispositions=load_dispositions(SCHEMA_DIR/'dispositions.csv')
    try:
        if args.command=='ingest':
            root=Path(args.drop).resolve()
            if not root.is_dir(): raise SystemExit(f'Drop directory not found: {root}')
            key=str(root); fp=fingerprint_drop(root)
            existing=db.execute('SELECT fingerprint FROM ingested_drops WHERE drop_key=?',(key,)).fetchone()
            if existing:
                if existing['fingerprint']!=fp: raise SystemExit('This drop path was already ingested with different contents. Use a fresh database for a new dataset.')
                print(f'Already ingested; no changes: {root}')
                return
            with db:
                ingest_leads(db,root,schemas,CRYPTO)
                ingest_events(db,root,dispositions)
                reconcile_events(db,dispositions)
                db.execute('INSERT INTO ingested_drops VALUES(?,?,?)',(key,fp,datetime.now(timezone.utc).isoformat()))
            print(f'Ingested {root}')
        elif args.command=='report':
            with db: reconcile_events(db,dispositions); build_reports(db,Path(args.out),schemas,dispositions)
            print(f'Reports written to {args.out}')
    finally: db.close()

if __name__=='__main__': main()
