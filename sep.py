import os
import sqlite3
import smtplib
import random
import secrets
from email.mime.text import MIMEText
from datetime import datetime, timedelta, time, date
from collections import defaultdict, OrderedDict

from flask import (Flask, render_template, request, flash, redirect,
                   url_for, g, session)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# ────────────────────────── アプリ設定 ──────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
DATABASE = 'smart_event.db'

# ────────────────────────── メール設定 ──────────────────────────
SMTP_SERVER   = "smtp.kuku.lu"
SMTP_PORT     = 465
SMTP_SENDER   = "smarteventplanner@postm.net"
SMTP_PASSWORD = "J[I2tH)gMIEr"        # ← 変更してください
OTP_EXPIRY_MINUTES = 10

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
        db.commit()

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
    send_email(invitee_email, subject, body)

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
        if datetime.strptime(user['otp_expiry'], '%Y-%m-%d %H:%M:%S.%f') < datetime.utcnow():
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
        # フロントから来る配列: slot-date[], slot-start[], slot-end[]
        slot_dates  = request.form.getlist('slot-date[]')
        slot_starts = request.form.getlist('slot-start[]')
        slot_ends   = request.form.getlist('slot-end[]')

        slots = []
        for d, s, e in zip(slot_dates, slot_starts, slot_ends):
            if not d or not s or not e:
                continue
            try:
                start_dt = datetime.strptime(f"{d} {s}", "%Y-%m-%d %H:%M")
                end_dt   = datetime.strptime(f"{d} {e}", "%Y-%m-%d %H:%M")
            except ValueError:
                flash('日付または時間の形式が正しくありません。', 'danger')
                return redirect(request.url)
            if end_dt <= start_dt:
                flash('終了時間は開始時間より後に設定してください。', 'warning')
                return redirect(request.url)
            slots.append({
                "start_iso": start_dt.isoformat(),
                "end_iso":   end_dt.isoformat(),
                "start":     start_dt,
                "end":       end_dt,
            })

        if not slots:
            flash('候補日を最低1つ追加してください。', 'warning')
            return redirect(request.url)

        # 開始時間でソート
        slots.sort(key=lambda x: x["start"])

        db = get_db()
        # イベント本体（代表として最初のスロットを格納）
        cur = db.execute("""
            INSERT INTO events(organizer_id, title, start_datetime, end_datetime)
            VALUES(?, ?, ?, ?)
        """, (session['user_id'], request.form['event-title'], slots[0]['start_iso'], slots[0]['end_iso']))
        event_id = cur.lastrowid

        # 候補スロットを保存
        for sl in slots:
            db.execute("""
                INSERT INTO event_slots(event_id, start_datetime, end_datetime)
                VALUES(?, ?, ?)
            """, (event_id, sl['start_iso'], sl['end_iso']))

        # 招待メール送信
        emails = request.form.getlist('emails[]')
        sent_count = 0
        for email in emails:
            email = (email or '').strip()
            if not email:
                continue
            token = secrets.token_urlsafe(16)
            db.execute(
                "INSERT INTO invitees(event_id, email, token) VALUES(?, ?, ?)",
                (event_id, email, token)
            )
            respond_url = url_for('respond', token=token, _external=True)
            send_invitation_email(email, request.form['event-title'], session['user_email'], respond_url)
            sent_count += 1

        db.commit()
        flash(f'{sent_count}名に招待を送信しました。', 'success')
        return redirect(url_for('invite_list'))

    # GET
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

    # POST 処理
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'decline':
            db.execute('UPDATE invitees SET status=\"declined\", responded_at=? WHERE id=?',
                       (datetime.utcnow(), invitee['id']))
            db.commit()
            return "<h2>不参加で受け付けました。</h2>"
        if action == 'attend':
            db.execute('DELETE FROM responses WHERE invitee_id=?', (invitee['id'],))
            available_slots = request.form.getlist('available_slots')
            valid_slots = set(row['start_datetime'] for row in slot_rows) if use_defined_slots else None
            for slot in available_slots:
                if use_defined_slots and slot not in valid_slots:
                    continue
                db.execute('INSERT INTO responses(invitee_id,available_slot) VALUES(?,?)',
                           (invitee['id'], slot))
            db.execute('UPDATE invitees SET status=\"attending\", responded_at=? WHERE id=?',
                       (datetime.utcnow(), invitee['id']))
            db.commit()
            return "<h2>ご回答ありがとうございました！</h2>"

    # 時間帯フィルタ
    slots = OrderedDict()
    if use_defined_slots:
        for row in slot_rows:
            start_dt = datetime.fromisoformat(row['start_datetime'])
            end_dt   = datetime.fromisoformat(row['end_datetime'])
            day_key = start_dt.strftime('%Y年%m月%d日 (%a)')
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

    return render_template('respond.html', event=event,
                           time_slots=slots, token=token)

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
            date_label = start_dt.strftime('%Y年%m月%d日 (%a)')
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
        slot_dt = datetime.fromisoformat(res['available_slot'])
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

    if event_ids:
        placeholders = ','.join('?' for _ in event_ids)
        invitee_rows = db.execute(
            f'''SELECT id, event_id, email, status, responded_at, token
                  FROM invitees
                 WHERE event_id IN ({placeholders})
                 ORDER BY email COLLATE NOCASE''',
            event_ids
        ).fetchall()
        status_labels = {
            'pending': '未回答',
            'attending': '参加',
            'declined': '不参加'
        }
        for inv in invitee_rows:
            invitees_map[inv['event_id']].append({
                'id': inv['id'],
                'email': inv['email'],
                'status': inv['status'],
                'status_label': status_labels.get(inv['status'], '不明'),
                'responded_at': inv['responded_at'],
                'token': inv['token']
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
        event_dict['start_display'] = start_dt.strftime('%Y年%m月%d日 %H:%M') if start_dt else '-'
        event_dict['end_display'] = end_dt.strftime('%Y年%m月%d日 %H:%M') if end_dt else None
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

        for row in rows:
            respond_url = url_for('respond', token=row['token'], _external=True)
            send_invitation_email(row['email'], event['title'], organizer_email, respond_url)

        flash(f'{len(rows)} 件の招待を再送しました。', 'success')
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

        # カスタム本文を追加（改行を <br> に置換）
        if custom_msg:
            body += "<p>{}</p>".format(custom_msg.replace('\n', '<br>'))

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
# ─────────────────── メイン ───────────────────
if __name__ == '__main__':
    init_db()

    # 証明書と秘密鍵（パスは実態に合わせて絶対パス推奨）
    ssl_context = (
        'smarteventplanner.coreone.work-crt.pem',   # サーバー証明書
        'smarteventplanner.coreone.work-key.pem',   # 秘密鍵
    )

    # ポートはそのまま 5000
    app.run(
        host='0.0.0.0',        # 外部公開するなら 0.0.0.0 が便利
        port=5000,
        ssl_context=ssl_context,
        debug=False             # 本番で使う場合は False に
import os
import sqlite3
import smtplib
import random
import secrets
from email.mime.text import MIMEText
from datetime import datetime, timedelta, time, date
from collections import defaultdict

from flask import (Flask, render_template, request, flash, redirect,
                   url_for, g, session)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# ────────────────────────── アプリ設定 ──────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
DATABASE = 'smart_event.db'

# ────────────────────────── メール設定 ──────────────────────────
SMTP_SERVER   = "smtp.kuku.lu"
SMTP_PORT     = 465
SMTP_SENDER   = "smarteventplanner@postm.net"
SMTP_PASSWORD = "J[I2tH)gMIEr"        # ← 変更してください
OTP_EXPIRY_MINUTES = 10

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
        db.commit()

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
    send_email(invitee_email, subject, body)

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
        if datetime.strptime(user['otp_expiry'], '%Y-%m-%d %H:%M:%S.%f') < datetime.utcnow():
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
        sd = request.form['start-date']   # YYYY-MM-DD
        ed = request.form['end-date']
        st = request.form['start-time']   # HH:MM
        et = request.form['end-time']

        start_dt = f"{sd}T{st}"
        end_dt   = f"{ed}T{et}"

        db   = get_db()
        cur  = db.execute('''
            INSERT INTO events(organizer_id,title,start_datetime,end_datetime)
            VALUES(?,?,?,?)
        ''', (session['user_id'], request.form['event-title'], start_dt, end_dt))
        db.commit()
        event_id = cur.lastrowid

        emails = request.form.getlist('emails[]')
        sent_count = 0
        for email in emails:
            if not email:
                continue
            token = secrets.token_urlsafe(16)
            db.execute('INSERT INTO invitees(event_id,email,token) VALUES(?,?,?)',
                       (event_id, email, token))
            db.commit()

            url_ = url_for('respond', token=token, _external=True)
            send_invitation_email(email, request.form['event-title'], session['user_email'], url_)
            sent_count += 1
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

    # POST 処理
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'decline':
            db.execute('UPDATE invitees SET status=\"declined\", responded_at=? WHERE id=?',
                       (datetime.utcnow(), invitee['id']))
            db.commit()
            return "<h2>不参加で受け付けました。</h2>"
        if action == 'attend':
            db.execute('DELETE FROM responses WHERE invitee_id=?', (invitee['id'],))
            for slot in request.form.getlist('available_slots'):
                db.execute('INSERT INTO responses(invitee_id,available_slot) VALUES(?,?)',
                           (invitee['id'], slot))
            db.execute('UPDATE invitees SET status=\"attending\", responded_at=? WHERE id=?',
                       (datetime.utcnow(), invitee['id']))
            db.commit()
            return "<h2>ご回答ありがとうございました！</h2>"

    # 時間帯フィルタ
    start_dt = datetime.fromisoformat(event['start_datetime'])
    end_dt   = datetime.fromisoformat(event['end_datetime'])
    daily_start = start_dt.hour
    daily_end   = end_dt.hour

    slots = defaultdict(list)
    cur_day = start_dt.date()
    while cur_day <= end_dt.date():
        for h in range(daily_start, daily_end):
            slot_dt = datetime.combine(cur_day, time(h))
            day_key = slot_dt.strftime('%Y年%m月%d日 (%a)')
            slots[day_key].append({'value': slot_dt.isoformat(),
                                   'display': slot_dt.strftime('%H:%M')})
        cur_day += timedelta(days=1)

    return render_template('respond.html', event=event,
                           time_slots=slots, token=token)

# ────────────────────────── 参加希望集計 ──────────────────────────
def find_best_schedule(event_id):
    """
    responses / invitees テーブルから
      - 各 1 時間スロットの参加可能人数
      - 最も参加人数が多いスロット
      - 参加率
    を計算して辞書で返す。
    必ず `details` キーを含むため、テンプレート側で安全に参照できる。
    """
    db = get_db()

    # 招待人数
    total_invitees = db.execute(
        'SELECT COUNT(*) FROM invitees WHERE event_id = ?',
        (event_id,)
    ).fetchone()[0]

    # 参加可回答
    responses = db.execute('''
        SELECT r.available_slot
          FROM responses r
          JOIN invitees i ON r.invitee_id = i.id
         WHERE i.event_id = ? AND i.status = 'attending'
    ''', (event_id,)).fetchall()

    # ❶ まだ誰も回答していない場合
    if not responses:
        return {
            "message": "まだ参加者から候補日時が集まっていません。",
            "total_invitees": total_invitees,
            "details": []          # 空配列を返しておくのがポイント
        }

    # ❷ スロットごとに人数をカウント
    from collections import defaultdict
    slot_counts = defaultdict(int)
    for res in responses:
        slot_dt = datetime.fromisoformat(res['available_slot'])
        key = slot_dt.strftime("%Y年%m月%d日 %H:%M")
        slot_counts[key] += 1

    # 人数の多い順に並べ替え
    sorted_slots = sorted(slot_counts.items(), key=lambda x: x[1], reverse=True)
    best_slot, max_attendees = sorted_slots[0]

    details = [{"time": k, "count": v} for k, v in sorted_slots]

    # ❸ 結果を辞書で返す
    return {
        "best_schedule": best_slot,
        "attendees": max_attendees,
        "total_invitees": total_invitees,
        "participation_rate": f"{(max_attendees / total_invitees * 100):.1f}%" if total_invitees else "0%",
        "details": details
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

    if event_ids:
        placeholders = ','.join('?' for _ in event_ids)
        invitee_rows = db.execute(
            f'''SELECT id, event_id, email, status, responded_at, token
                  FROM invitees
                 WHERE event_id IN ({placeholders})
                 ORDER BY email COLLATE NOCASE''',
            event_ids
        ).fetchall()
        status_labels = {
            'pending': '未回答',
            'attending': '参加',
            'declined': '不参加'
        }
        for inv in invitee_rows:
            invitees_map[inv['event_id']].append({
                'id': inv['id'],
                'email': inv['email'],
                'status': inv['status'],
                'status_label': status_labels.get(inv['status'], '不明'),
                'responded_at': inv['responded_at'],
                'token': inv['token']
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
        event_dict['start_display'] = start_dt.strftime('%Y年%m月%d日 %H:%M') if start_dt else '-'
        event_dict['end_display'] = end_dt.strftime('%Y年%m月%d日 %H:%M') if end_dt else None
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
    return render_template('invite_list.html', categorized_events=categorized)


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

        for row in rows:
            respond_url = url_for('respond', token=row['token'], _external=True)
            send_invitation_email(row['email'], event['title'], organizer_email, respond_url)

        flash(f'{len(rows)} 件の招待を再送しました。', 'success')
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
        iso = datetime.strptime(d['time'], '%Y年%m月%d日 %H:%M').isoformat()
        choices.append({'iso': iso, 'display': d['time'], 'count': d['count']})

    # ───────── POST ─────────
    if request.method == 'POST':
        chosen_iso  = request.form.get('final_datetime')
        new_title   = request.form.get('final_title') or event['title']
        custom_msg  = request.form.get('custom_message', '').strip()

        if not chosen_iso:
            flash('日時を選択してください。', 'warning')
            return redirect(request.url)

        start_dt = datetime.fromisoformat(chosen_iso)
        end_dt   = start_dt + timedelta(hours=1)

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

        # カスタム本文を追加（改行を <br> に置換）
        if custom_msg:
            body += "<p>{}</p>".format(custom_msg.replace('\n', '<br>'))

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
# ─────────────────── メイン ───────────────────
# ─────────────────── メイン ───────────────────
if __name__ == '__main__':
    init_db()

    # 証明書と秘密鍵（パスは実態に合わせて絶対パス推奨）
    ssl_context = (
        'smarteventplanner.coreone.work-crt.pem',   # サーバー証明書
        'smarteventplanner.coreone.work-key.pem',   # 秘密鍵
    )

    # ポートはそのまま 5000
    app.run(
        host='0.0.0.0',        # 外部公開するなら 0.0.0.0 が便利
        port=5000,
        ssl_context=ssl_context,
        debug=False             # 本番で使う場合は False に
    )

