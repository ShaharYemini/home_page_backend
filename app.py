from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os

app = Flask(__name__)
CORS(app, origins=["http://127.0.0.1:5500", "https://shaharyemini.github.io", "https://shaharyemini.github.io/homePage/"], supports_credentials=True)

# === CONFIGURATION ===
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")
TOKEN_URL = "https://oauth2.googleapis.com/token"

# === TOKEN STORAGE ===
def store_refresh_token(user_id, token):
    with open("refresh_token.txt", "w") as f:
        f.write(token)
    app.logger.info(f"Stored refresh token for user {user_id}")

# === ROUTES ===
@app.route("/auth", methods=["POST", "OPTIONS"])
def auth():
    if request.method == "OPTIONS":
        return "", 200  # Handle preflight request
    code = request.json.get("code")
    user_id = request.json.get("user_id", "default_user")
    app.logger.info(f"Received code: {code}, user_id: {user_id}")
    if not code:
        return jsonify({"error": "Missing authorization code"}), 400
    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }
    app.logger.info(f"Sending token exchange request with redirect_uri: {REDIRECT_URI}")
    r = requests.post(TOKEN_URL, data=data)
    if r.status_code != 200:
        details = r.json() if r.content else r.text
        app.logger.error(f"Token exchange failed: status={r.status_code}, details={details}")
        return jsonify({"error": "Failed to exchange code", "details": details}), r.status_code
    token_data = r.json()
    if token_data.get("refresh_token"):
        store_refresh_token(user_id, token_data.get("refresh_token"))
    return jsonify({
        "access_token": token_data.get("access_token"),
        "expires_in": token_data.get("expires_in")
    })

@app.route("/refresh", methods=["GET"])
def refresh():
    try:
        with open("refresh_token.txt", "r") as f:
            refresh_token = f.read().strip()
    except FileNotFoundError:
        return jsonify({"error": "No refresh token stored"}), 400
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }
    r = requests.post(TOKEN_URL, data=data)
    if r.status_code != 200:
        details = r.json() if r.content else r.text
        app.logger.error(f"Refresh token failed: status={r.status_code}, details={details}")
        return jsonify({"error": "Failed to refresh token", "details": details}), r.status_code
    token_data = r.json()
    return jsonify({
        "access_token": token_data.get("access_token"),
        "expires_in": token_data.get("expires_in")
    })

# === ENTRY POINT ===
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)