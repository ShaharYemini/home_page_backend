from flask import Flask, request, jsonify
from flask_cors import CORS

import requests
import os
import sqlite3

app = Flask(__name__)
CORS(app, origins=["http://127.0.0.1:5500", "https://shaharyemini.github.io/homePage/"])

# === CONFIGURATION ===
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")

TOKEN_URL = "https://oauth2.googleapis.com/token"

def init_db():
    conn = sqlite3.connect('tokens.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS tokens (id INTEGER PRIMARY KEY, refresh_token TEXT)')
    conn.commit()
    conn.close()

def store_refresh_token(token):
    conn = sqlite3.connect('tokens.db')
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO tokens (id, refresh_token) VALUES (1, ?)', (token,))
    conn.commit()
    conn.close()

def get_refresh_token():
    conn = sqlite3.connect('tokens.db')
    c = conn.cursor()
    c.execute('SELECT refresh_token FROM tokens WHERE id = 1')
    token = c.fetchone()
    conn.close()
    return token[0] if token else None

init_db()
# === ROUTES ===

@app.route("/auth", methods=["POST"])
def auth():
    code = request.json.get("code")
    if not code:
        return jsonify({"error": "Missing authorization code"}), 400
    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }
    r = requests.post(TOKEN_URL, data=data)
    if r.status_code != 200:
        try:
            details = r.json()
        except ValueError:
            details = r.text
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
        return jsonify({"error": "Failed to refresh token", "details": details}), 400
    token_data = r.json()
    return jsonify({
        "access_token": token_data.get("access_token"),
        "expires_in": token_data.get("expires_in")
    })


# === ENTRY POINT ===
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
