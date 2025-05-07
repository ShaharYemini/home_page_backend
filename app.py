import os
import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app, origins=["http://127.0.0.1:5500", "https://shaharyemini.github.io"], supports_credentials=True)

CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")
TOKEN_URL = "https://oauth2.googleapis.com/token"

def init_db():
    db_path = '/data/tokens.db'  # Use Render Disk path
    app.logger.info(f"Initializing database at {db_path}")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS tokens (id INTEGER PRIMARY KEY, refresh_token TEXT)')
    conn.commit()
    conn.close()
    app.logger.info(f"Database initialized, exists: {os.path.exists(db_path)}")

def store_refresh_token(token):
    db_path = '/data/tokens.db'
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO tokens (id, refresh_token) VALUES (1, ?)', (token,))
    conn.commit()
    conn.close()
    app.logger.info(f"Stored refresh token, db exists: {os.path.exists(db_path)}")

def get_refresh_token():
    db_path = '/data/tokens.db'
    app.logger.info(f"Checking for refresh token at {db_path}")
    if not os.path.exists(db_path):
        app.logger.error("tokens.db does not exist")
        return None
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT refresh_token FROM tokens WHERE id = 1')
    token = c.fetchone()
    conn.close()
    app.logger.info(f"Retrieved refresh token: {token[0] if token else None}")
    return token[0] if token else None

# Initialize DB on startup
init_db()

@app.route("/auth", methods=["POST"])
def auth():
    code = request.json.get("code")
    app.logger.info(f"Received auth code: {code}")
    if not code:
        return jsonify({"error": "Missing authorization code"}), 400
    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }
    app.logger.info(f"Exchanging code with redirect_uri: {REDIRECT_URI}")
    r = requests.post(TOKEN_URL, data=data)
    if r.status_code != 200:
        try:
            details = r.json()
        except ValueError:
            details = r.text
        app.logger.error(f"Token exchange failed: {details}")
        return jsonify({"error": "Failed to exchange code", "details": details}), 400
    token_data = r.json()
    if token_data.get("refresh_token"):
        store_refresh_token(token_data.get("refresh_token"))
    return jsonify({
        "access_token": token_data.get("access_token"),
        "expires_in": token_data.get("expires_in")
    })

@app.route("/refresh", methods=["GET"])
def refresh():
    refresh_token = get_refresh_token()
    app.logger.info(f"Refresh token: {refresh_token}")
    if not refresh_token:
        return jsonify({"error": "No refresh token stored"}), 400
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }
    r = requests.post(TOKEN_URL, data=data)
    if r.status_code != 200:
        try:
            details = r.json()
        except ValueError:
            details = r.text
        app.logger.error(f"Refresh token failed: {details}")
        return jsonify({"error": "Failed to refresh token", "details": details}), 400
    token_data = r.json()
    return jsonify({
        "access_token": token_data.get("access_token"),
        "expires_in": token_data.get("expires_in")
    })

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)