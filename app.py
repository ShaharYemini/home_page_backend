from flask import Flask, request, jsonify
from flask_cors import CORS

import requests
import os

app = Flask(__name__)
CORS(app, origins=["http://127.0.0.1:5500", "https://shaharyemini.github.io/homePage/"])

# === CONFIGURATION ===
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")

TOKEN_URL = "https://oauth2.googleapis.com/token"

# In-memory storage for refresh tokens (for demo only!)
TOKENS = {
    "refresh_token": None
}

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
        return jsonify({"error": "Failed to exchange code", "details": r.json()}), 400

    token_data = r.json()
    TOKENS["refresh_token"] = token_data.get("refresh_token")
    return jsonify({
        "access_token": token_data.get("access_token"),
        "expires_in": token_data.get("expires_in")
    })


@app.route("/refresh", methods=["GET"])
def refresh():
    refresh_token = TOKENS.get("refresh_token")
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
        return jsonify({"error": "Failed to refresh token", "details": r.json()}), 400

    token_data = r.json()
    return jsonify({
        "access_token": token_data.get("access_token"),
        "expires_in": token_data.get("expires_in")
    })


# === ENTRY POINT ===
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
