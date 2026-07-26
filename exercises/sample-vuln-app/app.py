"""
=====================================================================
 INTENTIONALLY VULNERABLE TRAINING APPLICATION. DO NOT DEPLOY
=====================================================================
 This tiny Flask app exists ONLY as a target for the security labs in
 the AI Cybersecurity Playbook (Lab 3 and Lab 6). It contains real,
 exploitable vulnerability patterns on purpose, so that audit tools
 and agents have something to find in a safe, local, disposable scope.

 Run it only on localhost, in a container or VM you can throw away.
 Never expose it to a network. Never reuse any of this code.
=====================================================================
"""

import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request, render_template_string, send_file

app = Flask(__name__)

# VULN (A07): hardcoded secret committed to source control.
# The audit should flag this; the fix is env-var + secret manager.
API_KEY = "sk-live-9f8e7d6c5b4a3210HARDCODED"
app.secret_key = "password123"  # VULN (A07): weak, hardcoded session secret

DB_PATH = "/tmp/vulnapp.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, role TEXT)"
    )
    return conn


@app.route("/")
def index():
    return "vulnapp training target; see /user, /ping, /download, /greet, /import"


@app.route("/user")
def user_lookup():
    # VULN (A03): SQL injection: user input concatenated into the query.
    username = request.args.get("username", "")
    conn = get_db()
    query = "SELECT id, username, role FROM users WHERE username = '%s'" % username
    rows = conn.execute(query).fetchall()
    return {"query": query, "results": rows}


@app.route("/ping")
def ping():
    # VULN (A03): OS command injection: shell=True with raw user input.
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return "<pre>%s</pre>" % out.decode(errors="replace")


@app.route("/download")
def download():
    # VULN (A01): path traversal: no validation on the file name.
    name = request.args.get("name", "notes.txt")
    return send_file(os.path.join("/tmp/uploads", name))


@app.route("/greet")
def greet():
    # VULN (A03): server-side template injection: user input inside the
    # template string instead of passed as data.
    name = request.args.get("name", "world")
    template = "<h1>Hello " + name + "!</h1>"
    return render_template_string(template)


@app.route("/import", methods=["POST"])
def import_data():
    # VULN (A08): insecure deserialization of attacker-controlled bytes.
    blob = request.get_data()
    obj = pickle.loads(blob)
    return {"imported": str(obj)}


@app.route("/report")
def report():
    # VULN (A05): error details leak internals to the client.
    try:
        1 / 0
    except Exception as exc:
        return f"debug trace: {exc!r} db={DB_PATH} key={API_KEY[:12]}...", 500


if __name__ == "__main__":
    # VULN (A05): debug mode on; interactive debugger exposed.
    app.run(host="127.0.0.1", port=5050, debug=True)
