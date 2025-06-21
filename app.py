from flask import Flask, request, render_template, redirect, session
import os, sqlite3, subprocess, time

app = Flask(__name__)
app.secret_key = 'insec_track_key'

DB = 'db/app.db'
EXAM_DURATION_SECONDS = 2 * 60 * 60  # 2 hours

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

@app.before_first_request
def init():
    if not os.path.exists(DB):
        os.makedirs('db', exist_ok=True)
        conn = sqlite3.connect(DB)
        with open('db/init.sql') as f:
            conn.executescript(f.read())
        conn.close()

@app.before_request
def check_exam_time():
    if 'user' in session:
        start = session.get('exam_start')
        if not start:
            session['exam_start'] = time.time()
        else:
            elapsed = time.time() - start
            if elapsed > EXAM_DURATION_SECONDS:
                session.clear()
                return render_template("terminated.html", reason="Time's up! Exam terminated.")

@app.route('/')
def home():
    if 'user' in session:
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pw = request.form['password']
        conn = get_db()
        # Medium level SQLi - no parametrized query here (intended)
        cur = conn.execute(f"SELECT * FROM users WHERE username='{user}' AND password='{pw}'")
        data = cur.fetchone()
        if data:
            session['user'] = user
            session['exam_start'] = time.time()
            return redirect('/dashboard')
        return "Login failed"
    return render_template("login.html")

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    return render_template("dashboard.html")

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if 'user' not in session:
        return redirect('/login')
    conn = get_db()
    if request.method == 'POST':
        comment = request.form['comment']
        # Escape < and > to prevent trivial XSS, but event handlers allowed
        comment = comment.replace('<', '&lt;').replace('>', '&gt;')
        conn.execute("INSERT INTO comments (content) VALUES (?)", (comment,))
        conn.commit()
    cur = conn.execute("SELECT * FROM comments")
    return render_template("comment.html", comments=cur.fetchall())

@app.route('/search')
def search():
    if 'user' not in session:
        return redirect('/login')
    q = request.args.get('q', '')
    blacklist = ['--', ';', '/*']
    if any(b in q.lower() for b in blacklist):
        return "Blocked keyword"
    conn = get_db()
    # Vulnerable to SQLi (medium sanitization)
    sql = f"SELECT * FROM users WHERE username LIKE '%{q}%'"
    rows = conn.execute(sql).fetchall()
    return render_template("search.html", results=rows)

@app.route('/logs')
def logs():
    if 'user' not in session:
        return redirect('/login')
    filename = request.args.get('file', 'access.log')
    if '../' in filename or '..\\' in filename:
        return "Directory traversal blocked"
    try:
        with open(f'logs/{filename}', 'r') as f:
            content = f.read()
        return render_template("logs.html", log=content)
    except:
        return "Log not found"

@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if 'user' not in session:
        return redirect('/login')
    result = ''
    if request.method == 'POST':
        ip = request.form['ip']
        # Allows digits and dots only, but will execute the command unsafely if tricked
        if all(c.isdigit() or c == '.' for c in ip):
            # Allowed IP format - ping executed safely
            result = subprocess.getoutput(f"ping -c 1 {ip}")
        else:
            # Potential injection allowed here (medium vulnerability)
            result = subprocess.getoutput(f"ping -c 1 {ip}")
    return render_template("ping.html", result=result)

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect('/login')
    uid = request.args.get('id', '1')
    conn = get_db()
    # No session-based access control (IDOR)
    cur = conn.execute(f"SELECT * FROM users WHERE id={uid}")
    user = cur.fetchone()
    return render_template("profile.html", user=user)

@app.route('/terminate', methods=['POST'])
def terminate():
    session.clear()
    return "Session terminated"

@app.errorhandler(404)
def page_not_found(e):
    return "Page not found", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0')
