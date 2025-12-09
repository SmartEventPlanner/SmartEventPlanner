import json
import os
import random
import re
import secrets
import smtplib
import sqlite3
from collections import defaultdict, OrderedDict
from datetime import datetime, timedelta, time, date
from email.mime.text import MIMEText
import html
import logging
import uuid
import hashlib
from typing import Optional

import requests
from flask import (Flask, render_template, request, flash, redirect,
                   url_for, g, session)
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# ────────────────────────── アプリ設定 ──────────────────────────
app = Flask(__name__, instance_relative_config=True)
app.config['SECRET_KEY'] = os.urandom(24)
DATABASE = 'smart_event.db'

app.config.from_pyfile('secrets.py', silent=True)

# ────────────────────────── 追加：AIログ設定 ──────────────────────────

LOG_VERBOSE_AI = True
AI_LOG_MAX_ERR_BODY = 300  # エラー時にresp.textを切り詰め表示
AI_LOG_NAME = "sep.ai"

ai_logger = logging.getLogger(AI_LOG_NAME)
ai_logger.setLevel(logging.DEBUG)
if not ai_logger.handlers:
    _h = logging.StreamHandler()
    _fmt = logging.Formatter('[%(asctime)s] %(levelname)s %(name)s %(message)s')
    _h.setFormatter(_fmt)
    ai_logger.addHandler(_h)

def _ctx_dict():
    try:
        return {
            "req_id": getattr(g, "req_id", None),
            "user_id": session.get("user_id"),
            "path": request.path,
            "method": request.method,
            "remote": request.remote_addr,
        }
    except Exception:
        return {}

def _ai_log(event: str, **fields):
    payload = {"event": event, **_ctx_dict(), **fields}
    try:
        ai_logger.info(json.dumps(payload, ensure_ascii=False))
    except Exception:
        ai_logger.info(f"{event} {fields}")  # フォールバック



# ────────────────────────── リクエスト相関IDとHTTP要約ログ ──────────────────────────
@app.before_request
def _assign_req_id():
    g.req_id = uuid.uuid4().hex[:12]
    g.req_ts = pytime.time()

@app.after_request
def _log_req_summary(response):
    try:
        dur_ms = int((pytime.time() - getattr(g, "req_ts", pytime.time())) * 1000)
        ai_logger.debug(json.dumps({
            "event": "http_request",
            "req_id": getattr(g, "req_id", None),
            "path": request.path,
            "method": request.method,
            "status": response.status_code,
            "duration_ms": dur_ms
        }, ensure_ascii=False))
    except Exception:
        pass
    return response


# ────────────────────────── メール設定 ──────────────────────────
SMTP_SERVER   = "smtp.kuku.lu"
SMTP_PORT     = 465
SMTP_SENDER   = "smarteventplanner@postm.net"
SMTP_PASSWORD = "J[I2tH)gMIEr"        # ← 変更してください
OTP_EXPIRY_MINUTES = 10

GEMINI_API_KEY = "AIzaSyDA5kg2zb_RSGXn4fgQeCoz1gyQMIxVXks"
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_API_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
)
AI_KEY_FPR = hashlib.sha256((GEMINI_API_KEY or "").encode()).hexdigest()[:10] if GEMINI_API_KEY else None


# ──────────────────────────日本語曜日ヘルパー──────────────────────────
WEEKDAYS_JA = "月火水木金土日"
def fmt_ja_date(dt: datetime) -> str:
    return dt.strftime('%Y年%m月%d日') + f"（{WEEKDAYS_JA[dt.weekday()]}）"

def fmt_ja_dt(dt: datetime) -> str:
    return fmt_ja_date(dt) + " " + dt.strftime('%H:%M')


# ────────────────────────── DB ヘルパ ──────────────────────────
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exc):
    db = getattr(g, '_database', None)
    if db:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('PRAGMA foreign_keys = ON;')

        db.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          is_confirmed INTEGER DEFAULT 0,
          one_time_code TEXT,
          otp_expiry DATETIME
        );

        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          organizer_id INTEGER NOT NULL,
          title TEXT NOT NULL,
          start_datetime TEXT NOT NULL,
          end_datetime TEXT NOT NULL,
          status TEXT DEFAULT 'pending',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(organizer_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS event_slots(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id INTEGER NOT NULL,
          start_datetime TEXT NOT NULL,
          end_datetime TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(event_id) REFERENCES events(id)
        );

        CREATE TABLE IF NOT EXISTS invitees(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id INTEGER NOT NULL,
          email TEXT NOT NULL,
          token TEXT UNIQUE NOT NULL,
          status TEXT DEFAULT 'pending',
          responded_at DATETIME,
          FOREIGN KEY(event_id) REFERENCES events(id)
        );

        CREATE TABLE IF NOT EXISTS responses(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          invitee_id INTEGER NOT NULL,
          available_slot TEXT NOT NULL,
          FOREIGN KEY(invitee_id) REFERENCES invitees(id)
        );

        CREATE TABLE IF NOT EXISTS schedules(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          title TEXT NOT NULL,
          event_date TEXT NOT NULL,
          start_time TEXT,
          end_time TEXT,
          is_all_day INTEGER DEFAULT 0,
          location TEXT,
          description TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        invitee_columns = {
            row['name']
            for row in db.execute('PRAGMA table_info(invitees)').fetchall()
        }
        if 'name' not in invitee_columns:
            db.execute('ALTER TABLE invitees ADD COLUMN name TEXT')

        db.commit()

# ──────────────────────────  ──────────────────────────


def build_default_final_body(title: str, start_dt: datetime, participant_count: Optional[int] = None) -> str:
    """
    決定メールの本文（テキストのみ、フッター含めない）
    - finalize_event の POST で必要ならフッターを追加するので、ここでは入れない
    """
    lines = [
        f"「{title}」は {start_dt.strftime('%Y年%m月%d日 %H:%M')} に開催いたします。",
    ]
    if participant_count is not None:
        lines.append(f"参加可能と回答：{participant_count}名")
    lines.append("必要な準備があれば各自で進めてください。")
    return "\n".join(lines)


# ────────────────────────── 認証デコレーター ──────────────────────────
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('ログインが必要です。', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

# ────────────────────────── メール送信 ──────────────────────────
def send_email(recipient, subject, body):
    msg = MIMEText(body, 'html')
    msg['Subject'] = subject
    msg['From']    = SMTP_SENDER
    msg['To']      = recipient
    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SMTP_SENDER, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"メール送信エラー: {e}")
        return False


def send_invitation_email(invitee_email, event_title, organizer_email, respond_url):
    subject = f"【出欠確認】{event_title}"
    body = f"""
    <p>{organizer_email} さんからの招待です。</p>
    <p><a href=\"{respond_url}\">こちら</a> からご回答ください。</p>
    """
    return send_email(invitee_email, subject, body)



from threading import Lock
import time as pytime

# ── 簡易キャッシュ（表示なし） ─────────────────
_ai_cache = {}
_ai_cache_ttl_sec = 600
_ai_cache_lock = Lock()

def _cache_get(key: str):
    now = pytime.time()
    with _ai_cache_lock:
        item = _ai_cache.get(key)
        if not item:
            return None
        exp, val = item
        if now > exp:
            _ai_cache.pop(key, None)
            return None
        return val

def _cache_set(key: str, value):
    with _ai_cache_lock:
        _ai_cache[key] = (pytime.time() + _ai_cache_ttl_sec, value)

# ── 簡易レート制限（ユーザー別） ─────────────────
_rate_limit_next = {}
_ai_block_until = 0.0
_ai_block_reason = ""


def _throttle(key: str, window_sec: float = 3.0):
    now = pytime.time()
    next_allowed = _rate_limit_next.get(key, 0.0)
    if now < next_allowed:
        wait = int(next_allowed - now + 0.999)
        _ai_log("app_throttle_block", key=key, wait_s=wait, window_s=window_sec)
        return True, wait
    _rate_limit_next[key] = now + window_sec
    _ai_log("app_throttle_pass", key=key, window_s=window_sec)
    return False, 0


def _ratelimit_headers(resp):
    if not resp or not getattr(resp, "headers", None):
        return {}
    hdr = resp.headers
    def get_lc(key_lc):
        for kk, vv in hdr.items():
            if kk.lower() == key_lc:
                return vv
        return None
    return {
        "x_ratelimit_limit":     get_lc("x-ratelimit-limit"),
        "x_ratelimit_remaining": get_lc("x-ratelimit-remaining"),
        "x_ratelimit_reset":     get_lc("x-ratelimit-reset"),
        "retry_after":           get_lc("retry-after"),
    }


def call_gemini(prompt, temperature=0.4):    # サーキット：連続429などで一時停止
    global _ai_block_until, _ai_block_reason
    now = pytime.time()
    if now < _ai_block_until:
        _ai_log("ai_circuit_block", until=_ai_block_until, reason=_ai_block_reason)
        return None, f"AI一時停止中: {_ai_block_reason}"

    if not GEMINI_API_KEY:
        _ai_log("ai_no_api_key")
        return None, 'Gemini API キーが設定されていません。'

    prompt_len = len(prompt or "")
    prompt_sha = hashlib.sha256((prompt or "").encode("utf-8")).hexdigest()[:16]
    req_meta = {
        "model": GEMINI_MODEL,
        "temperature": temperature,
        "prompt_len": prompt_len,
        "prompt_sha16": prompt_sha,
        "key_fpr": AI_KEY_FPR,
    }

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": temperature},
    }

    cache_key = hashlib.sha256((GEMINI_MODEL + "|" + str(temperature) + "|" + (prompt or "")).encode("utf-8")).hexdigest()
    cached = _cache_get(cache_key)
    if cached:
        _ai_log("ai_cache_hit", **req_meta)
        return cached, None

    _ai_log("ai_call_start", **req_meta)

    backoff = 1.0
    max_attempts = 4
    for attempt in range(1, max_attempts + 1):
        t0 = pytime.time()
        try:
            _ai_log("ai_http_attempt", attempt=attempt, **req_meta)
            resp = requests.post(
                GEMINI_API_URL,
                headers={"x-goog-api-key": GEMINI_API_KEY},  # URLに載せない
                json=payload,
                timeout=20,
            )
            dt_ms = int((pytime.time() - t0) * 1000)

            # 429 専用処理：ヘッダも丸めて記録
            if resp.status_code == 429:
                hdr = {k.lower(): v for k, v in resp.headers.items()
                       if k.lower() in ("date", "x-ratelimit-limit", "x-ratelimit-remaining",
                                        "x-ratelimit-reset", "retry-after", "content-type")}
                planned_delay = None
                if attempt < max_attempts:
                    ra = hdr.get("retry-after")
                    if ra and str(ra).isdigit():
                        planned_delay = float(ra)
                    else:
                        planned_delay = backoff + random.uniform(0.2, 0.6)
                _ai_log("ai_http_429", latency_ms=dt_ms, attempt=attempt,
                        planned_delay_s=planned_delay, headers=hdr, **req_meta)
                if attempt < max_attempts:
                    backoff = min(backoff * 2, 16)
                    pytime.sleep(max(1.0, planned_delay or backoff))
                    continue

            if not (200 <= resp.status_code < 300):
                hdr = {k.lower(): v for k, v in resp.headers.items()
                       if k.lower() in ("date", "x-ratelimit-limit", "x-ratelimit-remaining",
                                        "x-ratelimit-reset", "retry-after", "content-type")}
                _ai_log(
                    "ai_http_error",
                    status=resp.status_code,
                    latency_ms=dt_ms,
                    body_preview=resp.text[:AI_LOG_MAX_ERR_BODY] if resp.text else None,
                    attempt=attempt,
                    headers=hdr,
                    **req_meta
                )
                resp.raise_for_status()

            data = resp.json()
            text = ""
            cand_cnt = 0
            for cand in data.get("candidates", []):
                parts = cand.get("content", {}).get("parts", [])
                frag = "".join(p.get("text", "") for p in parts if "text" in p).strip()
                if frag and not text:
                    text = frag
                cand_cnt += 1
            _ai_log("ai_call_success", latency_ms=dt_ms, candidates=cand_cnt, out_len=len(text or ""), **req_meta)

            # 成功したらサーキット解除
            _ai_block_until = 0.0
            _ai_block_reason = ""

            if text:
                _cache_set(cache_key, text)
                return text, None

            _ai_log("ai_no_valid_text", **req_meta)
            return None, "Gemini から有効な応答が得られませんでした。"

        except requests.exceptions.HTTPError as he:
            status = getattr(getattr(he, "response", None), "status_code", "unknown")
            _ai_log("ai_http_exception", status=status, attempt=attempt, **req_meta)
            # 最後の試行で 429 → 一時停止（無駄打ち防止）
            if status == 429 and attempt >= max_attempts:
                _ai_block_reason = "upstream_quota_429"
                _ai_block_until = pytime.time() + 60  # 60秒ブレーク
            if status == 429 and attempt < max_attempts:
                pytime.sleep(backoff + random.uniform(0.2, 0.6))
                backoff = min(backoff * 2, 16)
                continue
            return None, f"Gemini APIエラー（status={status})"
        except Exception as exc:
            _ai_log("ai_call_exception", exc_type=type(exc).__name__, attempt=attempt, **req_meta)
            return None, "Gemini 呼び出しでエラーが発生しました。"

@app.route('/debug/ai/ping')
def debug_ai_ping():
    # ローカルのみ許可
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return "forbidden", 403
    txt, err = call_gemini("「pong」とだけ出力してください。", temperature=0)
    _ai_log("debug_ai_ping", ok=bool(txt), err=err)
    return ({"text": txt, "err": err}, 200 if txt else 503)

def extract_json_block(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r'\{.*?\}', text, re.S)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                return None
    return None


def format_japanese_datetime(iso_str):
    try:
        dt = datetime.fromisoformat(iso_str)
    except (TypeError, ValueError):
        return iso_str
    return dt.strftime('%Y年%m月%d日 %H:%M')

# ────────────────────────── 認証ルート（register / confirm / login / logout） ──────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email    = request.form['email']
        password = request.form['password']

        db   = get_db()
        user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()

        if user and user['is_confirmed']:
            flash('このメールアドレスは既に登録されています。', 'danger')
            return redirect(url_for('register'))

        otp = str(random.randint(100000, 999999))
        otp_expiry = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)

        password_hash = generate_password_hash(password)
        if user:
            db.execute('UPDATE users SET password_hash=?, one_time_code=?, otp_expiry=? WHERE email=?',
                       (password_hash, otp, otp_expiry, email))
        else:
            db.execute('INSERT INTO users(email,password_hash,one_time_code,otp_expiry) VALUES(?,?,?,?)',
                       (email, password_hash, otp, otp_expiry))
        db.commit()

        subject = f"認証コード {otp}"
        body = f"""
        <p>スマートイベントプランナーへようこそ！</p>
        <p>以下の認証コードを入力してください。（{OTP_EXPIRY_MINUTES}分間有効）</p>
        <h2>{otp}</h2>
        """
        send_email(email, subject, body)
        flash('認証コードを送信しました。', 'info')
        return redirect(url_for('confirm', email=email))
    return render_template('register.html')

@app.route('/confirm', methods=['GET', 'POST'])
def confirm():
    email = request.args.get('email')
    if request.method == 'POST':
        email = request.form['email']
        otp   = request.form['otp']
        db    = get_db()
        user  = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        if (not user) or (user['one_time_code'] != otp):
            flash('認証失敗。', 'danger')
            return redirect(url_for('confirm', email=email))
        try:
            otp_exp = datetime.fromisoformat(user['otp_expiry'])
        except Exception:
            try:
                otp_exp = datetime.strptime(user['otp_expiry'], '%Y-%m-%d %H:%M:%S')
            except Exception:
                otp_exp = None
        if (otp_exp is None) or (otp_exp < datetime.utcnow()):
            flash('認証コードの有効期限が切れています。', 'danger')
            return redirect(url_for('register'))
        db.execute('UPDATE users SET is_confirmed=1, one_time_code=NULL, otp_expiry=NULL WHERE id=?',
                   (user['id'],))
        db.commit()
        flash('認証完了。ログインしてください。', 'success')
        return redirect(url_for('login'))
    return render_template('confirm.html', email=email)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = request.form['email']
        password = request.form['password']
        db   = get_db()
        user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        if not user or not check_password_hash(user['password_hash'], password):
            flash('メールまたはパスワードが違います。', 'danger')
            return redirect(url_for('login'))
        if not user['is_confirmed']:
            flash('認証が完了していません。', 'warning')
            return redirect(url_for('confirm', email=email))
        session.clear()
        session['user_id']    = user['id']
        session['user_email'] = user['email']
        return redirect(url_for('calendar'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('ログアウトしました。', 'success')
    return redirect(url_for('login'))

# ────────────────────────── 基本画面 ──────────────────────────
@app.route('/')
def index():
    return redirect(url_for('calendar')) if 'user_id' in session else redirect(url_for('login'))

@app.route('/calendar')
@login_required
def calendar():
    db = get_db()
    rows = db.execute('SELECT * FROM schedules WHERE user_id=? ORDER BY event_date,start_time',
                      (session['user_id'],)).fetchall()
    schedules = [dict(r) for r in rows]
    return render_template('event.html', schedules=schedules)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        is_all_day = 'all-day' in request.form
        db = get_db()
        db.execute('''
          INSERT INTO schedules(user_id,title,event_date,start_time,end_time,is_all_day,location,description)
          VALUES(?,?,?,?,?,?,?,?)
        ''', (session['user_id'], request.form['event-title'], request.form['event-date'],
              None if is_all_day else request.form['start-time'],
              None if is_all_day else request.form['end-time'],
              is_all_day, request.form['event-location'], request.form['event-description']))
        db.commit()
        flash('予定を作成しました。', 'success')
        return redirect(url_for('calendar'))
    return render_template('create.html')

# ────────────────────────── 招待作成（時間帯指定） ──────────────────────────
@app.route('/invite', methods=['GET', 'POST'])
@login_required
def invite():
    if request.method == 'POST':
        raw_dates = request.form.getlist('slot-date[]')
        raw_start_times = request.form.getlist('slot-start[]')
        raw_end_times   = request.form.getlist('slot-end[]')

        slots = []
        for idx, date_raw in enumerate(raw_dates):
            date_raw = (date_raw or '').strip()
            if not date_raw:
                continue

            try:
                slot_date = datetime.strptime(date_raw, '%Y-%m-%d').date()
            except ValueError:
                flash('候補日の形式が正しくありません。', 'danger')
                return redirect(request.url)

            start_time_raw = raw_start_times[idx] if idx < len(raw_start_times) else ''
            end_time_raw   = raw_end_times[idx] if idx < len(raw_end_times) else ''

            start_time_raw = (start_time_raw or '').strip()
            end_time_raw   = (end_time_raw or '').strip()

            if (start_time_raw and not end_time_raw) or (end_time_raw and not start_time_raw):
                flash('開始時間と終了時間は両方入力してください。', 'warning')
                return redirect(request.url)

            if start_time_raw:
                try:
                    start_time = datetime.strptime(start_time_raw, '%H:%M').time()
                    end_time   = datetime.strptime(end_time_raw, '%H:%M').time()
                except ValueError:
                    flash('時間の形式が正しくありません。', 'danger')
                    return redirect(request.url)

                start_dt = datetime.combine(slot_date, start_time)
                end_dt   = datetime.combine(slot_date, end_time)
            else:
                start_dt = datetime.combine(slot_date, time.min)
                end_dt   = datetime.combine(slot_date, time(23, 59))

            if end_dt <= start_dt:
                flash('終了時間は開始時間より後に設定してください。', 'warning')
                return redirect(request.url)

            slots.append({
                'start': start_dt,
                'end': end_dt,
                'start_iso': start_dt.isoformat(),
                'end_iso': end_dt.isoformat(),
            })

        if not slots:
            flash('候補日を最低1つ追加してください。', 'warning')
            return redirect(request.url)

        slots.sort(key=lambda x: x['start'])

        db   = get_db()
        cur  = db.execute('''
            INSERT INTO events(organizer_id,title,start_datetime,end_datetime)
            VALUES(?,?,?,?)
        ''', (session['user_id'], request.form['event-title'], slots[0]['start_iso'], slots[0]['end_iso']))
        event_id = cur.lastrowid

        for slot in slots:
            db.execute('''
                INSERT INTO event_slots(event_id,start_datetime,end_datetime)
                VALUES(?,?,?)
            ''', (event_id, slot['start_iso'], slot['end_iso']))

        emails = request.form.getlist('emails[]')
        sent_count = 0
        for email in emails:
            if not email:
                continue
            token = secrets.token_urlsafe(16)
            db.execute('INSERT INTO invitees(event_id,email,token) VALUES(?,?,?)',
                       (event_id, email, token))

            url_ = url_for('respond', token=token, _external=True)
            if send_invitation_email(email, request.form['event-title'], session['user_email'], url_):
                sent_count += 1

        db.commit()
        flash(f'{sent_count}名に招待を送信しました。', 'success')
        return redirect(url_for('invite_list'))
    return render_template('create-invite.html')

# ────────────────────────── 参加回答 ──────────────────────────
@app.route('/respond/<token>', methods=['GET', 'POST'])
def respond(token):
    db = get_db()
    invitee = db.execute('SELECT * FROM invitees WHERE token=?', (token,)).fetchone()
    if not invitee:
        return "無効なリンクです。", 404
    event = db.execute('SELECT * FROM events WHERE id=?', (invitee['event_id'],)).fetchone()

    slot_rows = db.execute(
        'SELECT start_datetime, end_datetime FROM event_slots WHERE event_id=? ORDER BY start_datetime',
        (event['id'],)
    ).fetchall()
    use_defined_slots = bool(slot_rows)

    existing_responses = db.execute(
        'SELECT available_slot FROM responses WHERE invitee_id=?',
        (invitee['id'],)
    ).fetchall()

    error = None
    invitee_name = (invitee['name'] or '').strip()
    selected_slots = [row['available_slot'] for row in existing_responses]
    show_slots = bool(selected_slots)

    # POST 処理
    if request.method == 'POST':
        action = request.form.get('action')
        invitee_name = request.form.get('invitee_name', '').strip()
        selected_slots = request.form.getlist('available_slots')

        if not invitee_name:
            error = '氏名を入力してください。'
        elif action == 'decline':
            db.execute(
                'UPDATE invitees SET status=\"declined\", responded_at=?, name=? WHERE id=?',
                (datetime.utcnow(), invitee_name, invitee['id'])
            )
            db.commit()
            return "<h2>不参加で受け付けました。</h2>"
        elif action == 'attend':
            show_slots = True
            valid_slots = set(row['start_datetime'] for row in slot_rows) if use_defined_slots else None
            if use_defined_slots and not selected_slots:
                error = '参加可能な候補日時を少なくとも1つ選択してください。'
            else:
                db.execute('DELETE FROM responses WHERE invitee_id=?', (invitee['id'],))
                for slot in selected_slots:
                    if use_defined_slots and slot not in valid_slots:
                        continue
                    db.execute(
                        'INSERT INTO responses(invitee_id,available_slot) VALUES(?,?)',
                        (invitee['id'], slot)
                    )
                db.execute(
                    'UPDATE invitees SET status=\"attending\", responded_at=?, name=? WHERE id=?',
                    (datetime.utcnow(), invitee_name, invitee['id'])
                )
                db.commit()
                return "<h2>ご回答ありがとうございました！</h2>"
        else:
            error = '操作を選択してください。'

    # 時間帯フィルタ
    slots = OrderedDict()
    if use_defined_slots:
        for row in slot_rows:
            start_dt = datetime.fromisoformat(row['start_datetime'])
            end_dt   = datetime.fromisoformat(row['end_datetime'])
            day_key = fmt_ja_date(start_dt)
            slots.setdefault(day_key, [])
            slots[day_key].append({
                'value': row['start_datetime'],
                'display': f"{start_dt.strftime('%H:%M')}〜{end_dt.strftime('%H:%M')}"
            })
    else:
        start_dt = datetime.fromisoformat(event['start_datetime'])
        end_dt   = datetime.fromisoformat(event['end_datetime'])
        daily_start = start_dt.hour
        daily_end   = end_dt.hour

        cur_day = start_dt.date()
        while cur_day <= end_dt.date():
            for h in range(daily_start, daily_end):
                slot_dt = datetime.combine(cur_day, time(h))
                day_key = slot_dt.strftime('%Y年%m月%d日 (%a)')
                slots.setdefault(day_key, [])
                slots[day_key].append({
                    'value': slot_dt.isoformat(),
                    'display': f"{slot_dt.strftime('%H:%M')} 開始"
                })
            cur_day += timedelta(days=1)

    return render_template(
        'respond.html',
        event=event,
        time_slots=slots,
        token=token,
        error=error,
        invitee_name=invitee_name,
        selected_slots=selected_slots,
        show_slots=show_slots,
    )

# ────────────────────────── 参加希望集計 ──────────────────────────
def find_best_schedule(event_id):
    """
    responses / invitees テーブルから
      - 各候補日時の参加可能人数
      - 最も参加人数が多いスロット
      - 参加率
    を計算して辞書で返す。
    必ず `details` キーを含むため、テンプレート側で安全に参照できる。
    """
    db = get_db()

    total_invitees = db.execute(
        'SELECT COUNT(*) FROM invitees WHERE event_id = ?',
        (event_id,)
    ).fetchone()[0]

    slot_rows = db.execute(
        'SELECT start_datetime, end_datetime FROM event_slots WHERE event_id=? ORDER BY start_datetime',
        (event_id,)
    ).fetchall()

    responses = db.execute('''
        SELECT r.available_slot
          FROM responses r
          JOIN invitees i ON r.invitee_id = i.id
         WHERE i.event_id = ? AND i.status = 'attending'
    ''', (event_id,)).fetchall()

    if slot_rows:
        counts = {row['start_datetime']: 0 for row in slot_rows}
        for res in responses:
            if res['available_slot'] in counts:
                counts[res['available_slot']] += 1

        details = []
        for row in slot_rows:
            start_dt = datetime.fromisoformat(row['start_datetime'])
            end_dt = datetime.fromisoformat(row['end_datetime'])
            date_label = fmt_ja_date(start_dt)
            time_label = f"{start_dt.strftime('%H:%M')}〜{end_dt.strftime('%H:%M')}"

            details.append({
                'time': f"{date_label} {time_label}",
                'count': counts[row['start_datetime']],
                'start_iso': row['start_datetime'],
                'end_iso': row['end_datetime'],
                'date_label': date_label,
                'time_label': time_label
            })

        if not responses:
            return {
                'message': 'まだ参加者から候補日時が集まっていません。',
                'total_invitees': total_invitees,
                'details': details
            }

        best_detail = max(
            details,
            key=lambda d: (d['count'], -datetime.fromisoformat(d['start_iso']).timestamp())
        )
        max_attendees = best_detail['count']

        return {
            'best_schedule': best_detail['time'],
            'attendees': max_attendees,
            'total_invitees': total_invitees,
            'participation_rate': f"{(max_attendees / total_invitees * 100):.1f}%" if total_invitees else '0%',
            'details': details
        }

    if not responses:
        return {
            'message': 'まだ参加者から候補日時が集まっていません。',
            'total_invitees': total_invitees,
            'details': []
        }

    from collections import defaultdict
    slot_counts = defaultdict(int)
    for res in responses:
        slot_counts[res['available_slot']] += 1

    sorted_slots = sorted(slot_counts.items(), key=lambda x: x[1], reverse=True)

    best_iso, max_attendees = sorted_slots[0]

    details = []
    for iso, count in sorted_slots:
        slot_dt = datetime.fromisoformat(iso)
        date_label = slot_dt.strftime('%Y年%m月%d日 (%a)')
        time_label = f"{slot_dt.strftime('%H:%M')}〜{(slot_dt + timedelta(hours=1)).strftime('%H:%M')}"
        details.append({
            'time': f"{date_label} {time_label}",
            'count': count,
            'start_iso': iso,
            'end_iso': (slot_dt + timedelta(hours=1)).isoformat(),
            'date_label': date_label,
            'time_label': time_label
        })

    return {
        'best_schedule': details[0]['time'],
        'attendees': max_attendees,
        'total_invitees': total_invitees,
        'participation_rate': f"{(max_attendees / total_invitees * 100):.1f}%" if total_invitees else '0%',
        'details': details
    }


# ────────────────────────── 結果表示 ──────────────────────────
@app.route('/event/<int:event_id>/results')
@login_required
def event_results(event_id):
    db = get_db()
    event = db.execute('SELECT * FROM events WHERE id=? AND organizer_id=?',
                       (event_id, session['user_id'])).fetchone()
    if not event:
        return "アクセス権がありません。", 403
    result = find_best_schedule(event_id)
    result['event_title'] = event['title']
    invitees = db.execute('SELECT * FROM invitees WHERE event_id=?', (event_id,)).fetchall()
    return render_template('invite_result.html', result=result,
                           invitees=invitees, event=event)

# ────────────────────────── 招待リスト ──────────────────────────
@app.route('/invites')
@login_required
def invite_list():
    db = get_db()
    event_rows = db.execute('''
        SELECT e.id, e.title, date(e.created_at) AS created_on,
               e.start_datetime, e.end_datetime, e.status,
               (SELECT COUNT(*) FROM invitees WHERE event_id=e.id)                     AS total,
               (SELECT COUNT(*) FROM invitees WHERE event_id=e.id AND status='attending') AS attending,
               (SELECT COUNT(*) FROM invitees WHERE event_id=e.id AND status='pending')   AS pending
          FROM events e
         WHERE organizer_id=?
         ORDER BY e.created_at DESC
    ''', (session['user_id'],)).fetchall()

    event_ids = [row['id'] for row in event_rows]
    invitees_map = {event_id: [] for event_id in event_ids}

    invitee_rows = []
    responses_by_invitee = {}
    slot_labels_by_event = {}

    if event_ids:
        placeholders = ','.join('?' for _ in event_ids)
        invitee_rows = db.execute(
            f'''SELECT id, event_id, email, status, responded_at, token, name
                  FROM invitees
                 WHERE event_id IN ({placeholders})
                 ORDER BY email COLLATE NOCASE''',
            event_ids
        ).fetchall()

        slot_rows = db.execute(
            f'''SELECT event_id, start_datetime, end_datetime
                   FROM event_slots
                  WHERE event_id IN ({placeholders})
                  ORDER BY start_datetime''',
            event_ids
        ).fetchall()
        for row in slot_rows:
            start_dt = datetime.fromisoformat(row['start_datetime'])
            end_dt = datetime.fromisoformat(row['end_datetime'])
            date_label = fmt_ja_date(start_dt)
            time_label = f"{start_dt.strftime('%H:%M')}〜{end_dt.strftime('%H:%M')}"

            slot_labels_by_event.setdefault(row['event_id'], {})[row['start_datetime']] = {
                'date': date_label,
                'time': time_label,
                'display': f"{date_label} {time_label}"
            }

        invitee_ids = [row['id'] for row in invitee_rows]
        if invitee_ids:
            invitee_placeholders = ','.join('?' for _ in invitee_ids)
            response_rows = db.execute(
                f'''SELECT invitee_id, available_slot
                       FROM responses
                      WHERE invitee_id IN ({invitee_placeholders})
                      ORDER BY available_slot''',
                invitee_ids
            ).fetchall()
            for res in response_rows:
                responses_by_invitee.setdefault(res['invitee_id'], []).append(res['available_slot'])

        status_labels = {
            'pending': '未回答',
            'attending': '参加',
            'declined': '不参加'
        }
        for inv in invitee_rows:
            response_isos = responses_by_invitee.get(inv['id'], [])
            response_details = []
            slot_label_map = slot_labels_by_event.get(inv['event_id'], {})
            for iso in response_isos:
                label = slot_label_map.get(iso)
                if label:
                    response_details.append(label['display'])
                else:
                    try:
                        slot_start = datetime.fromisoformat(iso)
                        date_label = slot_start.strftime('%Y年%m月%d日 (%a)')
                        end_guess = slot_start + timedelta(hours=1)
                        time_label = f"{slot_start.strftime('%H:%M')}〜{end_guess.strftime('%H:%M')}"
                        response_details.append(f"{date_label} {time_label}")
                    except ValueError:
                        response_details.append(iso)

            responded_display = None
            if inv['responded_at']:
                try:
                    responded_dt = datetime.fromisoformat(inv['responded_at'])
                    responded_display = responded_dt.strftime('%Y/%m/%d %H:%M')
                except ValueError:
                    responded_display = inv['responded_at']

            invitees_map[inv['event_id']].append({
                'id': inv['id'],
                'email': inv['email'],
                'name': inv['name'],
                'status': inv['status'],
                'status_label': status_labels.get(inv['status'], '不明'),
                'responded_at': inv['responded_at'],
                'responded_display': responded_display,
                'token': inv['token'],
                'responses': response_details,
            })

    categorized = {
        'pending': [],
        'confirmed': [],
        'past': []
    }

    now = datetime.utcnow()
    for row in event_rows:
        event_dict = dict(row)
        start_dt = datetime.fromisoformat(row['start_datetime']) if row['start_datetime'] else None
        end_dt = datetime.fromisoformat(row['end_datetime']) if row['end_datetime'] else None
        event_dict['start_display'] = fmt_ja_dt(start_dt) if start_dt else '-'
        event_dict['end_display']   = fmt_ja_dt(end_dt) if end_dt else None

        event_dict['invitees'] = invitees_map.get(row['id'], [])

        if row['status'] == 'confirmed':
            if start_dt and start_dt < now:
                categorized['past'].append(event_dict)
            else:
                categorized['confirmed'].append(event_dict)
        else:
            categorized['pending'].append(event_dict)

    section_configs = [
        ('pending', '調整中の招待', 'まだ回答を待っている招待です。進捗を確認し、必要であればリマインドを送りましょう。'),
        ('confirmed', '決定済みの予定', '開催前の確定した予定です。追加で案内したい宛先があればここから送信できます。'),
        ('past', '開催済みの予定', 'すでに終了したイベントです。実施履歴としてご確認ください。')
    ]

    sections = []
    total_events = 0
    for key, title, description in section_configs:
        items = categorized[key]
        total_events += len(items)
        sections.append({
            'key': key,
            'title': title,
            'description': description,
            'entries': items
        })

    return render_template(
        'invite_list.html',
        categorized_sections=sections,
        total_events=total_events
    )


@app.route('/invites/<int:event_id>', methods=['POST'])
@login_required
def manage_invitees(event_id):
    db = get_db()
    event = db.execute(
        'SELECT * FROM events WHERE id=? AND organizer_id=?',
        (event_id, session['user_id'])
    ).fetchone()
    if not event:
        flash('イベントが見つからないか、権限がありません。', 'danger')
        return redirect(url_for('invite_list'))

    action = request.form.get('action')
    organizer_email = session.get('user_email', '')

    if action == 'resend':
        invitee_ids = request.form.getlist('invitee_ids')
        if not invitee_ids:
            flash('再送する宛先を選択してください。', 'warning')
            return redirect(url_for('invite_list'))

        placeholders = ','.join('?' for _ in invitee_ids)
        rows = db.execute(
            f'''SELECT email, token FROM invitees
                   WHERE event_id=? AND id IN ({placeholders})''',
            [event_id, *invitee_ids]
        ).fetchall()

        ok = 0; ng = 0
        for row in rows:
            respond_url = url_for('respond', token=row['token'], _external=True)  # ← これを追加
            if send_invitation_email(row['email'], event['title'], organizer_email, respond_url):
                ok += 1
            else:
                ng += 1

        msg = f'{ok} 件の招待を再送しました。'
        if ng:
            msg += f'（{ng} 件は送信に失敗）'
        flash(msg, 'success' if ng == 0 else 'warning')
        return redirect(url_for('invite_list'))

    if action == 'add':
        raw_text = request.form.get('new_emails', '')
        if not raw_text.strip():
            flash('追加するメールアドレスを入力してください。', 'warning')
            return redirect(url_for('invite_list'))

        normalized = raw_text.replace('\r', '\n').replace(',', '\n')
        candidates = [line.strip() for line in normalized.split('\n') if line.strip()]
        if not candidates:
            flash('有効なメールアドレスが見つかりませんでした。', 'warning')
            return redirect(url_for('invite_list'))

        existing_emails = {
            row['email'] for row in db.execute(
                'SELECT email FROM invitees WHERE event_id=?',
                (event_id,)
            ).fetchall()
        }

        added = 0
        skipped = 0
        for email in candidates:
            if email in existing_emails:
                skipped += 1
                continue
            token = secrets.token_urlsafe(16)
            db.execute(
                'INSERT INTO invitees(event_id,email,token) VALUES(?,?,?)',
                (event_id, email, token)
            )
            respond_url = url_for('respond', token=token, _external=True)
            send_invitation_email(email, event['title'], organizer_email, respond_url)
            added += 1
            existing_emails.add(email)

        db.commit()

        if added:
            msg = f'{added} 件のメールアドレスを追加し、招待を送信しました。'
            if skipped:
                msg += f' （{skipped} 件は既に招待済みでした）'
            flash(msg, 'success')
        else:
            flash('すべてのメールアドレスが既に招待済みでした。', 'info')
        return redirect(url_for('invite_list'))

    flash('無効な操作です。', 'danger')
    return redirect(url_for('invite_list'))


@app.route('/api/ai/generate-final-message', methods=['POST'])
@login_required
def api_generate_final_message():
    """
    選択された日時だけを使って、AIに「本文のみ」を生成させるエンドポイント。
    - フロントからは { event_id, slot: { iso: "YYYY-MM-DDTHH:MM:SS" } } を送る
    - イベント名や参加可能人数などは AI に送らない（プライバシー最小化）
    - 失敗時はローカル定型文でフォールバック
    """
    # レート制限
    blocked, wait = _throttle(f"genmsg:{session['user_id']}", 3.0)
    if blocked:
        return {'error': f'リクエストが多すぎます。{wait}秒後にお試しください。'}, 429

    # 入力取得
    data = request.get_json(silent=True) or {}
    event_id = data.get('event_id')
    slot = data.get('slot') or {}
    slot_iso = (slot.get('iso') or '').strip()

    if not event_id or not slot_iso:
        return {'error': '必要な情報が不足しています。'}, 400

    # 認可（自分のイベントか）
    db = get_db()
    ev = db.execute(
        'SELECT id FROM events WHERE id=? AND organizer_id=?',
        (event_id, session['user_id'])
    ).fetchone()
    if not ev:
        return {'error': 'イベントが見つからないか、権限がありません。'}, 404

    # 日時パース
    try:
        slot_dt = datetime.fromisoformat(slot_iso)
    except Exception:
        return {'error': '日時の形式が正しくありません。'}, 400

    ev = get_db().execute(
        'SELECT title FROM events WHERE id=? AND organizer_id=?',
        (event_id, session['user_id'])
    ).fetchone()
    title = ev['title'] if ev else 'イベント'
    message = build_default_final_body(title, slot_dt)  # 1〜2行の定型文
    _ai_log("local_message_generated", event_id=event_id, slot_iso=slot_iso)
    return {'message': message, 'fallback': True, 'source': 'local'}

@app.route('/api/ai/plan-finalization', methods=['POST'])
@login_required
def api_plan_finalization():
    blocked, wait = _throttle(f"planfinal:{session['user_id']}", 3.0)
    if blocked:
        return {'error': f'リクエストが多すぎます。{wait}秒後にお試しください。'}, 429
    # （以下、元の処理）
    data = request.get_json(silent=True) or {}
    event_id = data.get('event_id')
    choices = data.get('choices') or []

    if not event_id or not choices:
        return {'error': '必要な情報が不足しています。'}, 400

    db = get_db()
    event = db.execute(
        'SELECT * FROM events WHERE id=? AND organizer_id=?',
        (event_id, session['user_id'])
    ).fetchone()
    if not event:
        return {'error': 'イベントが見つかりません。'}, 404

    lines = []
    for idx, choice in enumerate(choices, 1):
        iso = choice.get('iso')
        display = choice.get('display') or format_japanese_datetime(iso)
        count = choice.get('count')
        if count is None:
            lines.append(f"{idx}. {display}")
        else:
            lines.append(f"{idx}. {display} — {count}名が参加可能")

    prompt = (
        "あなたはイベント主催者を支援するAIです。"
        "参加者に送る本文を提案してください。\n"
        f"イベント名: {event['title']}\n"
        "{\n"
        "  \"message\": \"日本語テキスト（HTMLタグなし・2〜3文・『当日のご参加をお待ちしております。』は入れない）\",\n"
        "}"
    )

    # --- AI呼び出し ---
    text, err = call_gemini(prompt, temperature=0.4)
    ai_used = False
    selected_iso = None
    msg_from_ai = None
    reason = None

    if text:
        obj = extract_json_block(text)
        if isinstance(obj, dict):
            selected_iso = (obj.get('selected_iso') or '').strip()
            msg_from_ai = (obj.get('message') or '').strip()
            reason = (obj.get('reason') or '').strip()
            ai_used = True

    # 候補に含まれていないISOが来た場合はフォールバック
    iso_set = {c.get('iso') for c in choices if c.get('iso')}
    if not selected_iso or selected_iso not in iso_set:
        best_choice = max(choices, key=lambda c: (c.get('count') or 0, c.get('iso') or ''))
        selected_iso = best_choice.get('iso')
        if not msg_from_ai:
            # 本文は定型文で補完
            sel_dt = datetime.fromisoformat(selected_iso)
            msg_from_ai = build_default_final_body(event['title'], sel_dt, participant_count=best_choice.get('count'))
        if not reason:
            reason = '参加可能人数が最も多い候補を選択しました。'
        return {
            'selected_iso': selected_iso,
            'message': msg_from_ai,
            'reason': reason,
            'fallback': True,
            'warning': err if err else None
        }

    # AIが正常応答：本文の禁止フレーズを念のため除去
    if msg_from_ai:
        msg_from_ai = msg_from_ai.replace('当日のご参加をお待ちしております。', '').strip()
    else:
        sel_dt = datetime.fromisoformat(selected_iso)
        msg_from_ai = build_default_final_body(event['title'], sel_dt)

    return {
        'selected_iso': selected_iso,
        'message': msg_from_ai,
        'reason': reason or 'AI提案',
        'fallback': not ai_used,
        'warning': err if err and ai_used is False else None
    }

# ────────────────────────── 予定確定 ──────────────────────────
@app.route('/event/<int:event_id>/finalize', methods=['GET', 'POST'])
@login_required
def finalize_event(event_id):
    """
    GET : 候補日時＋参加人数を一覧表示（choices）
    POST: 選択した日時でイベントを confirmed にし
          参加希望者全員へ決定メールを送信
    """
    db = get_db()

    # イベントが自分のものか確認
    event = db.execute(
        'SELECT * FROM events WHERE id=? AND organizer_id=?',
        (event_id, session['user_id'])
    ).fetchone()
    if not event:
        flash('イベントが見つからないか、権限がありません。', 'danger')
        return redirect(url_for('invite_list'))

    # 参加希望集計
    result = find_best_schedule(event_id)

    # 参加候補（日本語表示 → ISO 変換）
    choices = []
    for d in result.get('details', []):
        start_iso = d.get('start_iso')
        end_iso = d.get('end_iso')
        if start_iso:
            iso = start_iso
            display = d.get('time') or f"{d.get('date_label', '')} {d.get('time_label', '')}".strip()
        else:
            try:
                iso = datetime.strptime(d['time'], '%Y年%m月%d日 %H:%M').isoformat()
            except (KeyError, ValueError):
                continue
            display = d['time']
        choices.append({'iso': iso, 'display': display, 'count': d.get('count', 0), 'end_iso': end_iso})

    if result.get('message'):
        choices = []

    # ───────── POST ─────────
    if request.method == 'POST':
        chosen_iso  = request.form.get('final_datetime')
        new_title   = request.form.get('final_title') or event['title']
        custom_msg  = request.form.get('custom_message', '').strip()

        if not chosen_iso:
            flash('日時を選択してください。', 'warning')
            return redirect(request.url)

        start_dt = datetime.fromisoformat(chosen_iso)
        slot_row = db.execute(
            'SELECT end_datetime FROM event_slots WHERE event_id=? AND start_datetime=?',
            (event_id, chosen_iso)
        ).fetchone()
        if slot_row:
            end_dt = datetime.fromisoformat(slot_row['end_datetime'])
        else:
            explicit_end = next((c['end_iso'] for c in choices if c['iso'] == chosen_iso and c.get('end_iso')), None)
            end_dt = datetime.fromisoformat(explicit_end) if explicit_end else start_dt + timedelta(hours=1)

        # イベントを confirmed に更新
        db.execute("""
            UPDATE events
               SET title=?, start_datetime=?, end_datetime=?, status='confirmed'
             WHERE id=?
        """, (new_title, start_dt.isoformat(), end_dt.isoformat(), event_id))
        db.commit()

        # カレンダーへ自動追加／更新
        event_date = start_dt.date().isoformat()
        start_time = start_dt.strftime('%H:%M')
        end_time = end_dt.strftime('%H:%M')
        description = f'イベントID {event_id} の確定予定'
        existing_schedule = db.execute(
            'SELECT id FROM schedules WHERE user_id=? AND description=?',
            (session['user_id'], description)
        ).fetchone()

        if existing_schedule:
            db.execute(
                'UPDATE schedules SET title=?, event_date=?, start_time=?, end_time=? WHERE id=?',
                (new_title, event_date, start_time, end_time, existing_schedule['id'])
            )
        else:
            db.execute('''
                INSERT INTO schedules(user_id,title,event_date,start_time,end_time,is_all_day,location,description)
                VALUES(?,?,?,?,?,?,?,?)
            ''', (session['user_id'], new_title, event_date, start_time, end_time, 0, '', description))
        db.commit()

        # 出席予定者メール一覧
        attendees = db.execute("""
            SELECT email FROM invitees
             WHERE event_id=? AND status='attending'
        """, (event_id,)).fetchall()

        subject = f"【決定】{new_title}"
        body = (f"<p>以下のイベントが確定しました。</p>"
                f"<p><strong>{new_title}</strong><br>"
                f"{start_dt.strftime('%Y年%m月%d日 %H:%M')}〜</p>")

        include_footer = request.form.get('include_default_footer', '1') == '1'

        # カスタム本文を追加（改行を <br> に置換）
        if custom_msg:
            safe_msg = html.escape(custom_msg).replace('\n', '<br>')
            body += f"<p>{safe_msg}</p>"
            if include_footer:
                body += "<p>当日のご参加をお待ちしております。</p>"
        else:
            body += "<p>当日のご参加をお待ちしております。</p>"

        # メール送信
        for row in attendees:
            send_email(row['email'], subject, body)

        flash(f'決定メールを {len(attendees)} 名に送信しました。カレンダーにも追加済みです。', 'success')
        return redirect(url_for('invite_list'))

    # ───────── GET ─────────
    if not choices:
        flash('まだ参加希望が集まっていないため確定できません。', 'warning')
        return redirect(url_for('event_results', event_id=event_id))

    return render_template(
        'finalize_event.html',
        event=event,
        choices=choices,
        details=[{'time': c['display'], 'count': c['count']} for c in choices]  # 旧テンプレ互換
    )

@app.route('/event/<int:event_id>/email', methods=['GET', 'POST'])
@login_required
def email_event_group(event_id):
    """
    決定済みイベント向けの一斉メール送信:
      - group: attending / non_attending / all
      - subject, body を入力して送信
    非参加者 = 未回答(pending) + 不参加(declined)
    """
    db = get_db()
    event = db.execute(
        'SELECT * FROM events WHERE id=? AND organizer_id=?',
        (event_id, session['user_id'])
    ).fetchone()
    if not event:
        flash('イベントが見つからないか、権限がありません。', 'danger')
        return redirect(url_for('invite_list'))

    if event['status'] != 'confirmed':
        flash('このイベントはまだ決定していません。決定後に送信できます。', 'warning')
        return redirect(url_for('invite_list'))

    # 既定の件名/本文
    default_subject = f"【連絡】{event['title']}"
    start_dt = None
    try:
        start_dt = datetime.fromisoformat(event['start_datetime']) if event['start_datetime'] else None
    except Exception:
        pass

    if request.method == 'POST':
        group = request.form.get('group')
        subject = (request.form.get('subject') or default_subject).strip()
        body_text = (request.form.get('body') or '').strip()
        include_event_block = request.form.get('include_event_block') == '1'

        if not group:
            flash('送信対象を選択してください。', 'warning')
            return redirect(request.url)

        # 宛先抽出
        if group == 'attending':
            rows = db.execute(
                "SELECT email FROM invitees WHERE event_id=? AND status='attending'",
                (event_id,)
            ).fetchall()
        elif group == 'non_attending':
            rows = db.execute(
                "SELECT email FROM invitees WHERE event_id=? AND status!='attending'",
                (event_id,)
            ).fetchall()
        elif group == 'all':
            rows = db.execute(
                "SELECT email FROM invitees WHERE event_id=?",
                (event_id,)
            ).fetchall()
        else:
            flash('無効な送信対象です。', 'danger')
            return redirect(request.url)

        emails = [r['email'] for r in rows]
        if not emails:
            flash('対象の宛先がありません。', 'info')
            return redirect(request.url)

        # 本文生成（ユーザー入力はエスケープ＋改行を <br>）
        body_parts = []
        if include_event_block and start_dt:
            body_parts.append(
                f"<p><strong>{html.escape(event['title'])}</strong><br>"
                f"{start_dt.strftime('%Y年%m月%d日 %H:%M')}〜</p>"
            )
        if body_text:
            escaped_body = html.escape(body_text).replace("\n", "<br>")
            body_parts.append(f"<p>{escaped_body}</p>")

        # 何も書かれていない場合の最低限の文面
        if not body_parts:
            body_parts.append("<p>ご確認をお願いいたします。</p>")

        body_html = "".join(body_parts)

        ok = 0
        ng = 0
        for addr in emails:
            if send_email(addr, subject, body_html):
                ok += 1
            else:
                ng += 1

        msg = f'メールを {ok} 件送信しました。'
        if ng:
            msg += f'（{ng} 件は送信に失敗）'
        flash(msg, 'success' if ng == 0 else 'warning')
        return redirect(url_for('invite_list'))

    # GET: 画面表示
    return render_template(
        'email_send.html',
        event=event,
        default_subject=default_subject,
        default_body_text='',
    )



# ─────────────────── メイン ───────────────────
if __name__ == '__main__':
    init_db()

    app.run(
        host='0.0.0.0',  # 外部公開するなら 0.0.0.0
        port=6000,
        debug=False      # 本番は False 推奨
    )

