import json
import logging
import traceback
from datetime import datetime
from os import environ as env
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request
from werkzeug.middleware.proxy_fix import ProxyFix  # <-- added

# Load environment variables
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

# Force HTTPS for url_for's _external URLs
app.config["PREFERRED_URL_SCHEME"] = "https"

# Apply ProxyFix middleware to respect X-Forwarded headers (important on Azure)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # DEBUG for verbose output
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Log env vars used for Auth0 (avoid logging secrets in production!)
app.logger.debug(f'AUTH0_CLIENT_ID={env.get("AUTH0_CLIENT_ID")}')
app.logger.debug(f'AUTH0_DOMAIN={env.get("AUTH0_DOMAIN")}')

oauth = OAuth(app)

try:
    auth0_domain = env.get("AUTH0_DOMAIN")
    if not auth0_domain:
        raise ValueError("AUTH0_DOMAIN environment variable is not set")

    server_metadata_url = f'https://{auth0_domain}/.well-known/openid-configuration'
    app.logger.debug(f"Using Auth0 metadata URL: {server_metadata_url}")

    oauth.register(
        "auth0",
        client_id=env.get("AUTH0_CLIENT_ID"),
        client_secret=env.get("AUTH0_CLIENT_SECRET"),
        client_kwargs={
            "scope": "openid profile email",
        },
        server_metadata_url=server_metadata_url,
    )
except Exception as e:
    app.logger.error(f"Error registering OAuth client: {e}")
    app.logger.error(traceback.format_exc())
    raise


@app.route("/")
def home():
    return render_template(
        "home.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    try:
        token = oauth.auth0.authorize_access_token()
        session["user"] = token

        user_info = token.get("userinfo", {})
        user_id = user_info.get("sub", "unknown")
        email = user_info.get("email", "unknown")
        timestamp = datetime.utcnow().isoformat()
        app.logger.info(f"[LOGIN] user_id={user_id}, email={email}, timestamp={timestamp}")

        redirect_to = session.pop("redirect_after_login", "/")
        return redirect(redirect_to)
    except Exception as e:
        app.logger.error(f"Error in callback: {e}")
        app.logger.error(traceback.format_exc())
        return "An error occurred during login callback.", 500


@app.route("/login")
def login():
    try:
        redirect_uri = url_for("callback", _external=True)
        app.logger.debug(f"Redirect URI for login: {redirect_uri}")
        return oauth.auth0.authorize_redirect(redirect_uri=redirect_uri)
    except Exception as e:
        app.logger.error(f"Error during login redirect: {e}")
        app.logger.error(traceback.format_exc())
        return "An error occurred during login.", 500


@app.route("/logout")
def logout():
    session.clear()
    try:
        logout_url = (
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
        app.logger.debug(f"Logout URL: {logout_url}")
        return redirect(logout_url)
    except Exception as e:
        app.logger.error(f"Error during logout: {e}")
        app.logger.error(traceback.format_exc())
        return "An error occurred during logout.", 500


@app.route("/protected")
def protected():
    user = session.get("user")
    if user is None:
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
    app.run(host="0.0.0.0", port=int(env.get("PORT", 3000)))
