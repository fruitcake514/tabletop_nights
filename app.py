import sqlite3, os, random, uuid, requests, xml.etree.ElementTree as ET
from functools import wraps
import hashlib, hmac, base64, json, time, re as _re

from flask import Flask, jsonify, request, render_template, g, Response

app = Flask(__name__)
DATABASE   = os.environ.get('DATABASE_PATH', '/data/tabletop.db')
SECRET_KEY = os.environ.get('SECRET_KEY', '')
ADMIN_USER = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASS = os.environ.get('ADMIN_PASSWORD', 'changeme')
NTFY_URL   = os.environ.get('NTFY_URL', '')   # e.g. https://ntfy.sh/your-topic-name

_DEFAULT_KEYS = {'', 'change-me-in-production-please', 'change-me-in-production', 'secret'}
if SECRET_KEY in _DEFAULT_KEYS:
    import sys, secrets as _sec2
    SECRET_KEY = _sec2.token_hex(32)
    print("[SECURITY WARNING] SECRET_KEY not set — tokens won't survive restart. Set it in docker-compose.yml.", file=sys.stderr)

import threading as _threading
_login_attempts: dict = {}
_login_lock = _threading.Lock()
_LOGIN_WINDOW, _LOGIN_MAX = 300, 10

# ── JWT ──────────────────────────────────────────────────────────
def _b64(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()
def _unb64(s):
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)
def make_token(uid, username, is_admin=False):
    import secrets as _sec
    hdr = _b64(json.dumps({'alg':'HS256','typ':'JWT'}))
    exp = int(time.time()) + 86400 * 30
    pay = _b64(json.dumps({'sub':uid,'username':username,'is_admin':is_admin,'exp':exp,'jti':_sec.token_hex(16)}))
    sig = _b64(hmac.new(SECRET_KEY.encode(), f'{hdr}.{pay}'.encode(), hashlib.sha256).digest())
    return f'{hdr}.{pay}.{sig}'
def verify_token(tok):
    try:
        h,p,s = tok.split('.')
        expected = _b64(hmac.new(SECRET_KEY.encode(), f'{h}.{p}'.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(s, expected): return None
        d = json.loads(_unb64(p))
        if d.get('exp',0) < time.time(): return None
        return d
    except: return None
def login_required(f):
    @wraps(f)
    def wrap(*a,**k):
        tok = request.headers.get('Authorization','').replace('Bearer ','').strip()
        d = verify_token(tok)
        if not d: return jsonify({'error':'Unauthorized'}), 401
        g.user_id = d['sub']; g.username = d['username']; g.is_admin = d.get('is_admin',False)
        return f(*a,**k)
    return wrap
def admin_required(f):
    @wraps(f)
    def wrap(*a,**k):
        tok = request.headers.get('Authorization','').replace('Bearer ','').strip()
        d = verify_token(tok)
        if not d or not d.get('is_admin'): return jsonify({'error':'Admin only'}), 403
        g.user_id = d['sub']; g.username = d['username']; g.is_admin = True
        return f(*a,**k)
    return wrap

# ── DB ───────────────────────────────────────────────────────────
def get_db():
    db = getattr(g,'_db',None)
    if db is None:
        os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
        db = g._db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA journal_mode = WAL")
    return db
@app.teardown_appcontext
def close_db(e):
    db = getattr(g,'_db',None)
    if db: db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password TEXT NOT NULL, is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS games (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            bgg_id TEXT, name TEXT NOT NULL, year INTEGER, thumbnail TEXT, image TEXT,
            description TEXT, min_players INTEGER DEFAULT 1, max_players INTEGER DEFAULT 99,
            play_time INTEGER DEFAULT 0, weight REAL DEFAULT 0, bgg_rating REAL DEFAULT 0,
            play_count INTEGER DEFAULT 0, added_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS user_game_ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            game_id TEXT NOT NULL REFERENCES games(id) ON DELETE CASCADE,
            rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 10),
            notes TEXT, rated_at TEXT DEFAULT (datetime('now')),
            UNIQUE(user_id, game_id)
        );
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, date TEXT NOT NULL,
            location TEXT, notes TEXT, max_players INTEGER DEFAULT 4,
            is_active INTEGER DEFAULT 1, marked_played INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS event_games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            game_id TEXT, name TEXT NOT NULL, thumbnail TEXT,
            min_players INTEGER DEFAULT 1, max_players INTEGER DEFAULT 99,
            play_time INTEGER DEFAULT 0, added_by TEXT, is_host_pick INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS rsvps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            participant TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('yes','no','maybe')),
            updated_at TEXT DEFAULT (datetime('now')), UNIQUE(event_id, participant)
        );
        CREATE TABLE IF NOT EXISTS event_game_ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            event_game_id INTEGER NOT NULL REFERENCES event_games(id) ON DELETE CASCADE,
            participant TEXT NOT NULL,
            rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 10),
            rated_at TEXT DEFAULT (datetime('now')),
            UNIQUE(event_id, event_game_id, participant)
        );
        CREATE TABLE IF NOT EXISTS account_requests (
            id TEXT PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE,
            password TEXT NOT NULL, requested_at TEXT DEFAULT (datetime('now')),
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending','approved','denied'))
        );
        """)
        db.commit()
        _migrate(db)
        _ensure_admin(db)

def _migrate(db):
    """Add any missing columns to existing databases."""
    need = [
        ("users",       "is_admin",     "INTEGER DEFAULT 0"),
        ("event_games", "added_by",     "TEXT"),
        ("event_games", "is_host_pick", "INTEGER DEFAULT 0"),
    ]
    cache = {}
    for tbl, col, typedef in need:
        if tbl not in cache:
            cache[tbl] = {r[1] for r in db.execute(f"PRAGMA table_info({tbl})")}
        if col not in cache[tbl]:
            db.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {typedef}")
            cache[tbl].add(col)
            print(f"[MIGRATE] Added {tbl}.{col}")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS user_game_ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL, game_id TEXT NOT NULL,
            rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 10),
            notes TEXT, rated_at TEXT DEFAULT (datetime('now')), UNIQUE(user_id, game_id)
        );
        CREATE TABLE IF NOT EXISTS event_game_ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL, event_game_id INTEGER NOT NULL, participant TEXT NOT NULL,
            rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 10),
            rated_at TEXT DEFAULT (datetime('now')),
            UNIQUE(event_id, event_game_id, participant)
        );
        CREATE TABLE IF NOT EXISTS account_requests (
            id TEXT PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE,
            password TEXT NOT NULL, requested_at TEXT DEFAULT (datetime('now')),
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending','approved','denied'))
        );
    """)
    db.commit()

def _ensure_admin(db):
    if not db.execute("SELECT 1 FROM users WHERE is_admin=1").fetchone():
        uid = uuid.uuid4().hex[:16]
        db.execute("INSERT OR IGNORE INTO users(id,username,password,is_admin) VALUES(?,?,?,1)",
                   (uid, ADMIN_USER, _hash_pw(ADMIN_PASS)))
        db.commit()

# ── PASSWORD (scrypt) ────────────────────────────────────────────
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P, _SCRYPT_DKLEN = 16384, 8, 1, 64
_PBKDF2_ITERS = 200_000

def _hash_pw(pw):
    salt = os.urandom(32)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN)
    return f"s1${salt.hex()}${dk.hex()}"

def _check_pw(pw, stored):
    if not stored: return False
    if stored.startswith("s1$"):
        try:
            _, salt_hex, dk_hex = stored.split("$")
            actual = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt_hex),
                                    n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN)
            return hmac.compare_digest(actual, bytes.fromhex(dk_hex))
        except: return False
    else:  # legacy PBKDF2
        try:
            raw = base64.b64decode(stored)
            salt, dk = raw[:16], raw[16:]
            return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, _PBKDF2_ITERS), dk)
        except: return False

def _id():   return uuid.uuid4().hex[:16]
def _code(db):
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    for _ in range(100):
        c = ''.join(random.choices(chars,k=6))
        if not db.execute("SELECT 1 FROM events WHERE code=?",(c,)).fetchone(): return c
def rows(q): return [dict(r) for r in q.fetchall()]
def row(q):  r = q.fetchone(); return dict(r) if r else None

# ── PAGES ────────────────────────────────────────────────────────
@app.route('/')
def index(): return render_template('index.html')
@app.route('/favicon.ico')
def favicon():
    svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#111"/><text x="16" y="23" font-size="20" text-anchor="middle">🎲</text></svg>'
    return Response(svg, mimetype='image/svg+xml', headers={'Cache-Control':'public,max-age=86400'})

# ── AUTH ─────────────────────────────────────────────────────────
def _check_rate_limit(ip):
    now = time.time()
    with _login_lock:
        attempts = [t for t in _login_attempts.get(ip, []) if now - t < _LOGIN_WINDOW]
        if len(attempts) >= _LOGIN_MAX: return False
        attempts.append(now); _login_attempts[ip] = attempts
    return True
def _get_ip(): return request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()

@app.route('/api/auth/login', methods=['POST'])
def login():
    ip = _get_ip()
    if not _check_rate_limit(ip): return jsonify({'error':'Too many attempts. Wait 5 minutes.'}), 429
    d = request.json or {}
    u = (d.get('username') or '').strip(); p = d.get('password','')
    db = get_db()
    user = row(db.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE",(u,)))
    if not user or not _check_pw(p, user['password']): return jsonify({'error':'Invalid username or password'}), 401
    if not (user['password'] or '').startswith('s1$'):
        db.execute("UPDATE users SET password=? WHERE id=?", (_hash_pw(p), user['id'])); db.commit()
    return jsonify({'token':make_token(user['id'],user['username'],bool(user['is_admin'])),
                    'username':user['username'],'isAdmin':bool(user['is_admin'])})

@app.route('/api/auth/me')
@login_required
def me(): return jsonify({'id':g.user_id,'username':g.username,'isAdmin':g.is_admin})

@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def change_password():
    d = request.json or {}
    old_pw = d.get('oldPassword',''); new_pw = d.get('newPassword','')
    if len(new_pw) < 6: return jsonify({'error':'New password must be ≥6 chars'}), 400
    db = get_db()
    user = row(db.execute("SELECT * FROM users WHERE id=?",(g.user_id,)))
    if not _check_pw(old_pw, user['password']): return jsonify({'error':'Current password incorrect'}), 401
    db.execute("UPDATE users SET password=? WHERE id=?",(_hash_pw(new_pw),g.user_id)); db.commit()
    return jsonify({'ok':True})

@app.route('/api/auth/check-username')
def check_username():
    """Public endpoint — lets signup form check availability without an account."""
    u = (request.args.get('u') or '').strip()
    if not u: return jsonify({'available': False})
    db = get_db()
    taken = bool(db.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE",(u,)).fetchone())
    pending = bool(db.execute("SELECT 1 FROM account_requests WHERE username=? COLLATE NOCASE AND status='pending'",(u,)).fetchone())
    return jsonify({'available': not taken and not pending, 'taken': taken, 'pending': pending})

@app.route('/api/auth/request-account', methods=['POST'])
def request_account():
    d = request.json or {}
    username = (d.get('username') or '').strip()
    password = d.get('password', '')
    if not username or len(username) < 2: return jsonify({'error':'Username must be ≥2 characters'}), 400
    if len(password) < 6: return jsonify({'error':'Password must be ≥6 characters'}), 400
    if not _re.match(r'^[a-zA-Z0-9_-]+$', username):
        return jsonify({'error':'Letters, numbers, _ and - only'}), 400
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE",(username,)).fetchone():
        return jsonify({'error':'Username already taken'}), 409
    if db.execute("SELECT 1 FROM account_requests WHERE username=? COLLATE NOCASE AND status='pending'",(username,)).fetchone():
        return jsonify({'error':'A request for that username is already pending'}), 409
    rid = _id()
    db.execute("INSERT INTO account_requests(id,username,password) VALUES(?,?,?)", (rid, username, _hash_pw(password)))
    db.commit()
    _ntfy('New Account Request', f'"{username}" has requested an account on Tabletop Nights.')
    return jsonify({'ok': True})

# ── ADMIN ────────────────────────────────────────────────────────
@app.route('/api/admin/users')
@admin_required
def admin_users():
    return jsonify(rows(get_db().execute("SELECT id,username,is_admin,created_at FROM users ORDER BY created_at")))

@app.route('/api/admin/users', methods=['POST'])
@admin_required
def admin_create_user():
    d = request.json or {}
    username = (d.get('username') or '').strip(); password = d.get('password',''); is_admin = bool(d.get('isAdmin',False))
    if not username or len(username)<2: return jsonify({'error':'Username ≥2 chars'}), 400
    if len(password)<6: return jsonify({'error':'Password ≥6 chars'}), 400
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE",(username,)).fetchone():
        return jsonify({'error':'Username taken'}), 409
    uid = _id()
    db.execute("INSERT INTO users(id,username,password,is_admin) VALUES(?,?,?,?)",(uid,username,_hash_pw(password),1 if is_admin else 0))
    db.commit()
    return jsonify({'id':uid,'username':username,'isAdmin':is_admin}), 201

@app.route('/api/admin/users/<uid>', methods=['DELETE'])
@admin_required
def admin_delete_user(uid):
    if uid==g.user_id: return jsonify({'error':'Cannot delete yourself'}), 400
    get_db().execute("DELETE FROM users WHERE id=? AND is_admin=0",(uid,)); get_db().commit()
    return jsonify({'ok':True})

@app.route('/api/admin/users/<uid>/reset-password', methods=['POST'])
@admin_required
def admin_reset_pw(uid):
    d = request.json or {}; pw = d.get('password','')
    if len(pw)<6: return jsonify({'error':'≥6 chars required'}), 400
    db = get_db(); db.execute("UPDATE users SET password=? WHERE id=?",(_hash_pw(pw),uid)); db.commit()
    return jsonify({'ok':True})

@app.route('/api/admin/requests')
@admin_required
def admin_list_requests():
    return jsonify(rows(get_db().execute(
        "SELECT id,username,requested_at,status FROM account_requests ORDER BY requested_at DESC"
    )))

@app.route('/api/admin/requests/pending-count')
@admin_required
def admin_pending_count():
    n = get_db().execute("SELECT COUNT(*) c FROM account_requests WHERE status='pending'").fetchone()['c']
    return jsonify({'count': n})

@app.route('/api/admin/requests/<rid>/approve', methods=['POST'])
@admin_required
def admin_approve_request(rid):
    db = get_db()
    req = row(db.execute("SELECT * FROM account_requests WHERE id=? AND status='pending'",(rid,)))
    if not req: return jsonify({'error':'Not found or already processed'}), 404
    if db.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE",(req['username'],)).fetchone():
        db.execute("UPDATE account_requests SET status='denied' WHERE id=?",(rid,)); db.commit()
        return jsonify({'error':'Username taken — request auto-denied'}), 409
    uid = _id()
    db.execute("INSERT INTO users(id,username,password,is_admin) VALUES(?,?,?,0)",(uid, req['username'], req['password']))
    db.execute("UPDATE account_requests SET status='approved' WHERE id=?",(rid,))
    db.commit()
    return jsonify({'ok':True,'username':req['username']})

@app.route('/api/admin/requests/<rid>/deny', methods=['POST'])
@admin_required
def admin_deny_request(rid):
    db = get_db()
    r = db.execute("UPDATE account_requests SET status='denied' WHERE id=? AND status='pending'",(rid,))
    db.commit()
    if r.rowcount == 0: return jsonify({'error':'Not found or already processed'}), 404
    return jsonify({'ok':True})

def _ntfy(title, msg, priority='default'):
    if not NTFY_URL: return
    try:
        requests.post(NTFY_URL, data=msg.encode(),
                      headers={'Title':title,'Priority':priority,'Tags':'busts_in_silhouette'}, timeout=5)
    except Exception: pass

# ── COLLECTION ───────────────────────────────────────────────────
@app.route('/api/collection')
@login_required
def get_collection():
    db = get_db()
    # avg_rating = combined average of owner rating + all guest event ratings for this game
    return jsonify(rows(db.execute("""
        SELECT g.*,
               (SELECT rating FROM user_game_ratings WHERE user_id=? AND game_id=g.id) as my_rating,
               (SELECT notes  FROM user_game_ratings WHERE user_id=? AND game_id=g.id) as my_notes,
               ROUND(COALESCE((
                   SELECT AVG(r) FROM (
                       SELECT CAST(ugr.rating AS REAL) r FROM user_game_ratings ugr WHERE ugr.game_id=g.id
                       UNION ALL
                       SELECT CAST(egr.rating AS REAL) r FROM event_game_ratings egr
                       JOIN event_games eg ON eg.id=egr.event_game_id WHERE eg.game_id=g.id
                   )
               ), 0), 1) as avg_rating,
               (SELECT COUNT(*) FROM (
                   SELECT 1 FROM user_game_ratings WHERE game_id=g.id
                   UNION ALL
                   SELECT 1 FROM event_game_ratings egr
                   JOIN event_games eg ON eg.id=egr.event_game_id WHERE eg.game_id=g.id
               )) as rating_count
        FROM games g WHERE g.user_id=? ORDER BY g.name
    """,(g.user_id,g.user_id,g.user_id))))

@app.route('/api/collection', methods=['POST'])
@login_required
def add_game():
    d = request.json or {}
    if not d.get('name'): return jsonify({'error':'Name required'}), 400
    db = get_db(); gid = _id()
    db.execute("""INSERT INTO games(id,user_id,bgg_id,name,year,thumbnail,image,description,
                   min_players,max_players,play_time,weight,bgg_rating) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
               (gid,g.user_id,d.get('bggId'),d['name'],d.get('year'),
                d.get('thumbnail'),d.get('image'),d.get('description'),
                d.get('minPlayers',1),d.get('maxPlayers',99),
                d.get('playTime',0),d.get('weight',0),d.get('bggRating',0)))
    db.commit()
    gm = row(db.execute("SELECT * FROM games WHERE id=?",(gid,)))
    gm['my_rating'] = None; gm['my_notes'] = None; gm['avg_rating'] = 0; gm['rating_count'] = 0
    return jsonify(gm), 201

@app.route('/api/collection/<gid>', methods=['DELETE'])
@login_required
def del_game(gid):
    get_db().execute("DELETE FROM games WHERE id=? AND user_id=?",(gid,g.user_id)); get_db().commit()
    return jsonify({'ok':True})

@app.route('/api/collection/<gid>/rate', methods=['POST'])
@login_required
def rate_game(gid):
    d = request.json or {}; rating = d.get('rating'); notes = (d.get('notes') or '').strip()
    db = get_db()
    if not db.execute("SELECT 1 FROM games WHERE id=? AND user_id=?",(gid,g.user_id)).fetchone():
        return jsonify({'error':'Not in your collection'}), 404
    if rating is None:
        db.execute("DELETE FROM user_game_ratings WHERE user_id=? AND game_id=?",(g.user_id,gid)); db.commit()
        return jsonify({'ok':True,'rating':None})
    rating = int(rating)
    if not 1<=rating<=10: return jsonify({'error':'Rating 1–10'}), 400
    db.execute("""INSERT INTO user_game_ratings(user_id,game_id,rating,notes,rated_at) VALUES(?,?,?,?,datetime('now'))
                  ON CONFLICT(user_id,game_id) DO UPDATE SET rating=excluded.rating,notes=excluded.notes,rated_at=excluded.rated_at""",
               (g.user_id,gid,rating,notes))
    db.commit()
    # Return updated avg so UI can refresh
    avg = row(db.execute("""
        SELECT ROUND(AVG(r),1) avg, COUNT(*) cnt FROM (
            SELECT CAST(ugr.rating AS REAL) r FROM user_game_ratings ugr WHERE ugr.game_id=?
            UNION ALL
            SELECT CAST(egr.rating AS REAL) r FROM event_game_ratings egr
            JOIN event_games eg ON eg.id=egr.event_game_id WHERE eg.game_id=?
        )
    """,(gid,gid)))
    return jsonify({'ok':True,'rating':rating,'notes':notes,'avg_rating':avg['avg'],'rating_count':avg['cnt']})

# ── BGG ──────────────────────────────────────────────────────────
# All endpoints are PUBLIC — no login required (guests use them too).
# No tokens, no sessions, no cookies. All endpoints use public XML APIs only.

_UA = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9',
}

def _net_err(e):
    m = str(e).lower()
    if 'resolve' in m or 'name' in m: return 'Cannot reach BoardGameGeek — check internet access.'
    if 'timeout' in m: return 'BoardGameGeek timed out. Try again.'
    return f'BGG unavailable ({str(e)[:60]})'

@app.route('/api/bgg/search')
def bgg_search():
    """Search using BGG XML API v2 /search — fully public, no auth."""
    q = request.args.get('q','').strip()
    if not q: return jsonify([])
    try:
        r = requests.get('https://boardgamegeek.com/xmlapi2/search',
                         params={'query':q,'type':'boardgame','exact':0}, headers=_UA, timeout=12)
        if r.status_code in (401,403,429):
            return jsonify({'error':f'BGG returned {r.status_code}','bgg_down':True}), 502
        r.raise_for_status()
        root = ET.fromstring(r.text)
        out = []
        for item in root.findall('item'):
            bid = item.get('id','')
            nm_el = item.find('name[@type="primary"]') or item.find('name')
            nm = (nm_el.get('value','') if nm_el is not None else '').strip()
            yr_el = item.find('yearpublished')
            yr = (yr_el.get('value','') if yr_el is not None else '').strip()
            if bid and nm: out.append({'bggId':bid,'name':nm,'year':yr})
            if len(out) >= 15: break
        return jsonify(out)
    except ET.ParseError:
        return jsonify({'error':'BGG returned unexpected data.','bgg_down':True}), 502
    except Exception as e:
        return jsonify({'error':_net_err(e),'bgg_down':True}), 502

@app.route('/api/bgg/thumbs')
def bgg_thumbs():
    """
    Batch thumbnail+playtime fetch using XML API v1 (supports comma-separated IDs).
    Returns {bggId: {thumbnail, year, name, playTime}} — no auth needed.
    """
    ids_param = request.args.get('ids','').strip()
    if not ids_param: return jsonify({})
    ids = [i.strip() for i in ids_param.split(',') if i.strip() and _re.match(r'^\d+$',i.strip())][:15]
    if not ids: return jsonify({})
    try:
        r = requests.get(f'https://boardgamegeek.com/xmlapi/boardgame/{",".join(ids)}',
                         params={'stats':1}, headers=_UA, timeout=15)
        if r.status_code in (401,403,429): return jsonify({})
        r.raise_for_status()
        root = ET.fromstring(r.text)
        out = {}
        for item in root.findall('boardgame'):
            bid = item.get('objectid','')
            if not bid: continue
            # Thumbnail — direct child text element in v1
            thumb = (item.findtext('thumbnail') or '').strip()
            # Year
            yr_el = item.find('yearpublished')
            yr = (yr_el.text or '').strip() if yr_el is not None else ''
            # Name — look for primary="true" attribute (v1 style)
            nm = ''
            for n in item.findall('name'):
                if n.get('primary') == 'true': nm = (n.text or '').strip(); break
            if not nm:
                n = item.find('name')
                if n is not None: nm = (n.text or '').strip()
            # Play time — text content in v1
            pt = 0
            pt_el = item.find('playingtime')
            if pt_el is not None:
                try: pt = int((pt_el.text or '0').strip() or '0')
                except: pt = 0
            # min/max players
            def _ti(tag):
                el = item.find(tag)
                if el is None: return 0
                try: return int((el.text or '0').strip() or '0')
                except: return 0
            out[bid] = {'thumbnail':thumb,'year':yr,'name':nm,'playTime':pt,
                        'minPlayers':_ti('minplayers') or 1,'maxPlayers':_ti('maxplayers') or 99}
        return jsonify(out)
    except Exception:
        return jsonify({})

@app.route('/api/bgg/thing/<bgg_id>')
def bgg_thing(bgg_id):
    """Full game details — tries v1 XML, then v2 XML, then HTML scrape."""
    if not _re.match(r'^\d+$',bgg_id): return jsonify({'error':'Invalid ID'}), 400
    for fn in (_bgg_xml_v1, _bgg_xml_v2, _bgg_html):
        result = fn(bgg_id)
        if result and result.get('name'):
            result['bggId'] = bgg_id
            return jsonify(result)
    return jsonify({'error':'Could not load from BGG. Add manually.','bgg_down':True}), 502

def _parse_xml_v1(root):
    """Parse BGG XML API v1 response — elements use text content, not value= attributes."""
    item = root.find('boardgame')
    if item is None: return None
    def _ti(tag, default=0):
        el = item.find(tag)
        if el is None: return default
        try: return int((el.text or str(default)).strip())
        except: return default
    def _tf(path, default=0.0):
        el = item.find(path)
        if el is None: return default
        try: return round(float((el.text or str(default)).strip()), 2)
        except: return default
    nm = ''
    for n in item.findall('name'):
        if n.get('primary') == 'true': nm = (n.text or '').strip(); break
    if not nm:
        n = item.find('name')
        if n is not None: nm = (n.text or '').strip()
    yr_el = item.find('yearpublished')
    yr = (yr_el.text or '').strip() if yr_el is not None else ''
    desc = (item.findtext('description') or '').replace('&#10;','\n')
    desc = _re.sub(r'<[^>]+>','',desc).strip()[:500]
    return {
        'name': nm, 'year': yr,
        'thumbnail': (item.findtext('thumbnail') or '').strip(),
        'image':     (item.findtext('image') or '').strip(),
        'description': desc,
        'minPlayers': _ti('minplayers',1) or 1,
        'maxPlayers': _ti('maxplayers',99) or 99,
        'playTime':   _ti('playingtime',0),
        'weight':     _tf('.//averageweight'),
        'bggRating':  _tf('.//average'),
    }

def _parse_xml_v2(root):
    """Parse BGG XML API v2 response — elements use value= attributes."""
    item = root.find('item')
    if item is None: return None
    def _ti(tag, default=0):
        el = item.find(tag)
        if el is None: return default
        try: return int(el.get('value', str(default)).strip() or str(default))
        except: return default
    def _tf(path, default=0.0):
        el = item.find(path)
        if el is None: return default
        try: return round(float(el.get('value', str(default)).strip() or str(default)), 2)
        except: return default
    nm_el = item.find('name[@type="primary"]') or item.find('name')
    nm = (nm_el.get('value','') if nm_el is not None else '').strip()
    yr_el = item.find('yearpublished')
    yr = (yr_el.get('value','') if yr_el is not None else '').strip()
    desc = (item.findtext('description') or '').replace('&#10;','\n')
    desc = _re.sub(r'<[^>]+>','',desc).strip()[:500]
    return {
        'name': nm, 'year': yr,
        'thumbnail': (item.findtext('thumbnail') or '').strip(),
        'image':     (item.findtext('image') or '').strip(),
        'description': desc,
        'minPlayers': _ti('minplayers',1) or 1,
        'maxPlayers': _ti('maxplayers',99) or 99,
        'playTime':   _ti('playingtime',0),
        'weight':     _tf('.//averageweight'),
        'bggRating':  _tf('.//average'),
    }

def _bgg_xml_v1(bgg_id):
    try:
        r = requests.get(f'https://boardgamegeek.com/xmlapi/boardgame/{bgg_id}',
                         params={'stats':1}, headers=_UA, timeout=12)
        if r.status_code in (401,403,429): return None
        r.raise_for_status()
        return _parse_xml_v1(ET.fromstring(r.text))
    except: return None

def _bgg_xml_v2(bgg_id):
    try:
        r = requests.get('https://boardgamegeek.com/xmlapi2/thing',
                         params={'id':bgg_id,'stats':1}, headers=_UA, timeout=12)
        if r.status_code in (401,403,429): return None
        r.raise_for_status()
        return _parse_xml_v2(ET.fromstring(r.text))
    except: return None

def _bgg_html(bgg_id):
    try:
        from bs4 import BeautifulSoup
        r = requests.get(f'https://boardgamegeek.com/boardgame/{bgg_id}',
                         headers={**_UA,'Accept':'text/html,*/*'}, timeout=12)
        r.raise_for_status()
        soup = BeautifulSoup(r.text,'html.parser')
        res = {'bggId':bgg_id,'name':'','year':'','thumbnail':'','image':'','description':'',
               'minPlayers':1,'maxPlayers':99,'playTime':0,'weight':0.0,'bggRating':0.0}
        for script in soup.find_all('script'):
            txt = script.string or ''
            for pat in [r'GEEK\.geekitemPreload\s*=\s*(\{.+?\});',
                        r'window\.geekitemPreload\s*=\s*(\{.+?\});']:
                m = _re.search(pat,txt,_re.DOTALL)
                if m:
                    try:
                        it = json.loads(m.group(1)).get('item',{})
                        res.update({'name':it.get('name',''),'year':str(it.get('yearpublished','')),
                                    'thumbnail':it.get('thumbnail',''),'image':it.get('image',''),
                                    'minPlayers':int(it.get('minplayers',1) or 1),
                                    'maxPlayers':int(it.get('maxplayers',99) or 99),
                                    'playTime':int(it.get('playingtime',0) or 0),
                                    'weight':round(float(it.get('averageweight',0) or 0),2),
                                    'bggRating':round(float((it.get('stats',{}) or {}).get('average',0) or 0),2)})
                        d = _re.sub(r'<[^>]+>','',it.get('description','') or '').strip()
                        res['description'] = d[:500]
                        if res['name']: return res
                    except: pass
        og = lambda p: (soup.find('meta',property=p) or {}).get('content','')
        t = og('og:title'); m = _re.match(r'^(.+?)\s*\((\d{4})\)$',t)
        res.update({'name':m.group(1).strip() if m else t,'year':m.group(2) if m else '',
                    'thumbnail':og('og:image'),'image':og('og:image'),'description':og('og:description')[:500]})
        return res if res['name'] else None
    except: return None

# ── EVENTS ───────────────────────────────────────────────────────
@app.route('/api/events')
@login_required
def get_events():
    db = get_db()
    evts = rows(db.execute("""
        SELECT e.*, COUNT(DISTINCT ry.id) rsvp_yes, COUNT(DISTINCT rn.id) rsvp_no
        FROM events e
        LEFT JOIN rsvps ry ON ry.event_id=e.id AND ry.status='yes'
        LEFT JOIN rsvps rn ON rn.event_id=e.id AND rn.status='no'
        WHERE e.user_id=? GROUP BY e.id ORDER BY e.date DESC
    """,(g.user_id,)))
    for ev in evts:
        ev['games'] = rows(db.execute("SELECT * FROM event_games WHERE event_id=?",(ev['id'],)))
    return jsonify(evts)

@app.route('/api/events', methods=['POST'])
@login_required
def create_event():
    d = request.json or {}
    if not d.get('name'): return jsonify({'error':'Name required'}), 400
    if not d.get('date'): return jsonify({'error':'Date required'}), 400
    db = get_db()
    eid = _id(); code = _code(db)
    db.execute("INSERT INTO events(id,user_id,code,name,date,location,notes,max_players) VALUES(?,?,?,?,?,?,?,?)",
               (eid,g.user_id,code,d['name'],d['date'],d.get('location'),d.get('notes'),d.get('maxPlayers',4)))
    for gid in (d.get('games') or []):
        gm = row(db.execute("SELECT * FROM games WHERE id=? AND user_id=?",(gid,g.user_id)))
        if gm:
            db.execute("INSERT INTO event_games(event_id,game_id,name,thumbnail,min_players,max_players,play_time,added_by,is_host_pick) VALUES(?,?,?,?,?,?,?,?,1)",
                       (eid,gm['id'],gm['name'],gm['thumbnail'],gm['min_players'],gm['max_players'],gm['play_time'],g.username))
    db.commit()
    ev = row(db.execute("SELECT * FROM events WHERE id=?",(eid,)))
    ev['games'] = rows(db.execute("SELECT * FROM event_games WHERE event_id=?",(eid,)))
    ev['rsvp_yes']=0; ev['rsvp_no']=0
    return jsonify(ev), 201

@app.route('/api/events/<eid>')
@login_required
def get_event(eid):
    db = get_db()
    ev = row(db.execute("SELECT * FROM events WHERE id=? AND user_id=?",(eid,g.user_id)))
    if not ev: return jsonify({'error':'Not found'}), 404
    ev['games'] = rows(db.execute("""
        SELECT eg.*, ROUND(COALESCE(AVG(egr.rating),0),1) avg_rating, COUNT(egr.id) rating_count
        FROM event_games eg
        LEFT JOIN event_game_ratings egr ON egr.event_game_id=eg.id AND egr.event_id=?
        WHERE eg.event_id=? GROUP BY eg.id
    """,(eid,eid)))
    ev['rsvps'] = rows(db.execute("SELECT participant,status FROM rsvps WHERE event_id=? ORDER BY updated_at",(eid,)))
    return jsonify(ev)

@app.route('/api/events/<eid>', methods=['DELETE'])
@login_required
def del_event(eid):
    get_db().execute("DELETE FROM events WHERE id=? AND user_id=?",(eid,g.user_id)); get_db().commit()
    return jsonify({'ok':True})

@app.route('/api/events/<eid>/toggle-active', methods=['POST'])
@login_required
def toggle_active(eid):
    db = get_db()
    ev = row(db.execute("SELECT * FROM events WHERE id=? AND user_id=?",(eid,g.user_id)))
    if not ev: return jsonify({'error':'Not found'}), 404
    new = 0 if ev['is_active'] else 1
    db.execute("UPDATE events SET is_active=? WHERE id=?",(new,eid)); db.commit()
    return jsonify({'is_active':new})

@app.route('/api/events/<eid>/mark-played', methods=['POST'])
@login_required
def mark_played(eid):
    db = get_db()
    ev = row(db.execute("SELECT * FROM events WHERE id=? AND user_id=?",(eid,g.user_id)))
    if not ev: return jsonify({'error':'Not found'}), 404
    if ev['marked_played']: return jsonify({'error':'Already marked'}), 400
    db.execute("UPDATE events SET marked_played=1 WHERE id=?",(eid,))
    db.execute("""UPDATE games SET play_count=play_count+1
                  WHERE id IN (SELECT game_id FROM event_games WHERE event_id=? AND game_id IS NOT NULL)
                  AND user_id=?""",(eid,g.user_id))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/events/<eid>/games/<int:egid>', methods=['DELETE'])
@login_required
def remove_event_game(eid,egid):
    db = get_db()
    if not row(db.execute("SELECT id FROM events WHERE id=? AND user_id=?",(eid,g.user_id))):
        return jsonify({'error':'Not found'}), 404
    db.execute("DELETE FROM event_games WHERE id=? AND event_id=?",(egid,eid)); db.commit()
    return jsonify({'ok':True})

# ── STATS ────────────────────────────────────────────────────────
@app.route('/api/stats')
@login_required
def stats():
    db = get_db(); uid = g.user_id
    s = {
        'totalGames':  row(db.execute("SELECT COUNT(*) c FROM games WHERE user_id=?",(uid,)))['c'],
        'totalEvents': row(db.execute("SELECT COUNT(*) c FROM events WHERE user_id=?",(uid,)))['c'],
        'totalPlays':  row(db.execute("SELECT COALESCE(SUM(play_count),0) c FROM games WHERE user_id=?",(uid,)))['c'],
        'upcoming':    row(db.execute("SELECT COUNT(*) c FROM events WHERE user_id=? AND date>datetime('now')",(uid,)))['c'],
        'rated':       row(db.execute("SELECT COUNT(*) c FROM user_game_ratings ugr JOIN games g ON g.id=ugr.game_id WHERE g.user_id=?",(uid,)))['c'],
    }
    s['topGames'] = rows(db.execute("""
        SELECT g.id,g.name,g.thumbnail,g.play_count,COALESCE(ugr.rating,0) my_rating
        FROM games g LEFT JOIN user_game_ratings ugr ON ugr.game_id=g.id AND ugr.user_id=?
        WHERE g.user_id=? ORDER BY g.play_count DESC LIMIT 6
    """,(uid,uid)))
    s['unplayed'] = rows(db.execute("""
        SELECT g.id,g.name,g.thumbnail,g.play_count,COALESCE(ugr.rating,0) my_rating
        FROM games g LEFT JOIN user_game_ratings ugr ON ugr.game_id=g.id AND ugr.user_id=?
        WHERE g.user_id=? AND g.play_count=0 ORDER BY g.name LIMIT 6
    """,(uid,uid)))
    s['nextUp'] = rows(db.execute("""
        SELECT e.*, COUNT(ry.id) rsvp_yes FROM events e
        LEFT JOIN rsvps ry ON ry.event_id=e.id AND ry.status='yes'
        WHERE e.user_id=? AND e.date>datetime('now') GROUP BY e.id ORDER BY e.date ASC LIMIT 4
    """,(uid,)))
    for ev in s['nextUp']:
        ev['games'] = rows(db.execute("SELECT * FROM event_games WHERE event_id=?",(ev['id'],)))
    return jsonify(s)

# ── PUBLIC JOIN ──────────────────────────────────────────────────
@app.route('/api/join/<code>')
def pub_event(code):
    db = get_db()
    ev = row(db.execute("SELECT * FROM events WHERE code=? COLLATE NOCASE",(code.upper(),)))
    if not ev: return jsonify({'error':'Event not found'}), 404
    ev['games'] = rows(db.execute("""
        SELECT eg.*, ROUND(COALESCE(AVG(egr.rating),0),1) avg_rating, COUNT(egr.id) rating_count
        FROM event_games eg
        LEFT JOIN event_game_ratings egr ON egr.event_game_id=eg.id AND egr.event_id=?
        WHERE eg.event_id=? GROUP BY eg.id
    """,(ev['id'],ev['id'])))
    ev['rsvp_yes'] = row(db.execute("SELECT COUNT(*) c FROM rsvps WHERE event_id=? AND status='yes'",(ev['id'],)))['c']
    ev['rsvp_no']  = row(db.execute("SELECT COUNT(*) c FROM rsvps WHERE event_id=? AND status='no'",(ev['id'],)))['c']
    return jsonify(ev)

@app.route('/api/join/<code>/rsvp', methods=['POST'])
def pub_rsvp(code):
    db = get_db()
    ev = row(db.execute("SELECT * FROM events WHERE code=? COLLATE NOCASE",(code.upper(),)))
    if not ev: return jsonify({'error':'Not found'}), 404
    if not ev['is_active']: return jsonify({'error':'Event closed'}), 403
    d = request.json or {}
    participant = (d.get('participant') or '').strip(); status = d.get('status','')
    if not participant: return jsonify({'error':'Name required'}), 400
    if status not in ('yes','no','maybe'): return jsonify({'error':'Bad status'}), 400
    db.execute("""INSERT INTO rsvps(event_id,participant,status,updated_at) VALUES(?,?,?,datetime('now'))
                  ON CONFLICT(event_id,participant) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at""",
               (ev['id'],participant,status))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/join/<code>/add-game', methods=['POST'])
def pub_add_game(code):
    db = get_db()
    ev = row(db.execute("SELECT * FROM events WHERE code=? COLLATE NOCASE",(code.upper(),)))
    if not ev: return jsonify({'error':'Not found'}), 404
    if not ev['is_active']: return jsonify({'error':'Event closed'}), 403
    d = request.json or {}
    name = (d.get('name') or '').strip(); participant = (d.get('participant') or '').strip()
    if not name: return jsonify({'error':'Game name required'}), 400
    if not participant: return jsonify({'error':'Your name required'}), 400
    if db.execute("SELECT 1 FROM event_games WHERE event_id=? AND LOWER(name)=LOWER(?)",(ev['id'],name)).fetchone():
        return jsonify({'error':'Already on the list'}), 409
    cursor = db.execute("""INSERT INTO event_games(event_id,game_id,name,thumbnail,min_players,max_players,play_time,added_by,is_host_pick)
                           VALUES(?,NULL,?,?,?,?,?,?,0)""",
                        (ev['id'],name,d.get('thumbnail',''),d.get('minPlayers',1),d.get('maxPlayers',99),d.get('playTime',0),participant))
    db.commit()
    return jsonify(row(db.execute("SELECT * FROM event_games WHERE id=?",(cursor.lastrowid,)))), 201

@app.route('/api/join/<code>/rate', methods=['POST'])
def pub_rate(code):
    db = get_db()
    ev = row(db.execute("SELECT * FROM events WHERE code=? COLLATE NOCASE",(code.upper(),)))
    if not ev: return jsonify({'error':'Not found'}), 404
    d = request.json or {}
    participant = (d.get('participant') or '').strip(); egid = d.get('eventGameId'); rating = d.get('rating')
    if not participant: return jsonify({'error':'Name required'}), 400
    if rating is None:
        db.execute("DELETE FROM event_game_ratings WHERE event_id=? AND event_game_id=? AND participant=?",(ev['id'],egid,participant))
        db.commit(); return jsonify({'ok':True,'rating':None})
    rating = int(rating)
    if not 1<=rating<=10: return jsonify({'error':'Rating 1–10'}), 400
    if not row(db.execute("SELECT 1 FROM event_games WHERE id=? AND event_id=?",(egid,ev['id']))):
        return jsonify({'error':'Game not in event'}), 400
    db.execute("""INSERT INTO event_game_ratings(event_id,event_game_id,participant,rating,rated_at) VALUES(?,?,?,?,datetime('now'))
                  ON CONFLICT(event_id,event_game_id,participant) DO UPDATE SET rating=excluded.rating,rated_at=excluded.rated_at""",
               (ev['id'],egid,participant,rating))
    db.commit()
    avg = row(db.execute("SELECT ROUND(AVG(rating),1) avg, COUNT(*) cnt FROM event_game_ratings WHERE event_id=? AND event_game_id=?",(ev['id'],egid)))
    return jsonify({'ok':True,'avg':avg['avg'],'count':avg['cnt']})

@app.route('/api/join/<code>/my-ratings/<participant>')
def pub_my_ratings(code,participant):
    db = get_db()
    ev = row(db.execute("SELECT id FROM events WHERE code=? COLLATE NOCASE",(code.upper(),)))
    if not ev: return jsonify({}), 404
    rs = rows(db.execute("SELECT event_game_id,rating FROM event_game_ratings WHERE event_id=? AND participant=?",(ev['id'],participant)))
    return jsonify({str(r['event_game_id']):r['rating'] for r in rs})

try:
    init_db()
except Exception as _boot_err:
    import sys
    print(f'[FATAL] Could not initialize database: {_boot_err}', file=sys.stderr)
    raise

if __name__=='__main__':
    app.run(host='0.0.0.0',port=5000,debug=os.environ.get('FLASK_DEBUG','0')=='1')
