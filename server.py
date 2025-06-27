"""Python Flask WebApp Auth0 integration example"""

import json
import logging
from datetime import datetime
from os import environ as env
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request

# Load environment variables
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)


# Controllers API
@app.route("/")
def home():
    return render_template(
        "home.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token

    # Log user login
    user_info = token.get("userinfo", {})
    user_id = user_info.get("sub", "unknown")
    email = user_info.get("email", "unknown")
    timestamp = datetime.utcnow().isoformat()
    app.logger.info(f"[LOGIN] user_id={user_id}, email={email}, timestamp={timestamp}")

    redirect_to = session.pop("redirect_after_login", "/")
    return redirect(redirect_to)


@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


@app.route("/protected")
def protected():
    user = session.get("user")
    if user is None:
        # Log unauthorized attempt
        app.logger.warning(f"[UNAUTHORIZED ACCESS] Attempt to access /protected at {datetime.utcnow().isoformat()}")
        session["redirect_after_login"] = request.path
        return redirect(url_for("login"))

    user_info = user.get("userinfo", {})
    user_id = user_info.get("sub", "unknown")
    email = user_info.get("email", "unknown")
    timestamp = datetime.utcnow().isoformat()
    app.logger.info(f"[ACCESS] /protected accessed by user_id={user_id}, email={email}, timestamp={timestamp}")

    return render_template("protected.html", user=user)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000))
