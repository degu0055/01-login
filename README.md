<!-- 

Repo link:
https://github.com/degu0055/01-login 
-->
# Flask Auth0 Login Example

This is a simple Flask web application demonstrating how to implement user login with Auth0 using the Authlib library.

## Prerequisites

- Python 3.x
- An Auth0 account
- Your Auth0 application configured with callback/logout URLs

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/flask-auth0-example.git
cd flask-auth0-example
```

### 2. Create a Virtual Environment (Optional but recommended)

```bash
python -m venv venv
source venv/bin/activate   # On Windows use: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install Flask Authlib python-dotenv
```

> Alternatively, you can create a `requirements.txt` file:

```
Flask
Authlib
python-dotenv
```

Then install with:

```bash
pip install -r requirements.txt
```

### 4. Create Environment Variables

Create a `.env` file in your project root with the following content:

```
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_DOMAIN=your-auth0-domain
APP_SECRET_KEY=your-random-secret-key
```

To generate a secure `APP_SECRET_KEY`:

```bash
openssl rand -hex 32
```

### 5. Configure Auth0

In your [Auth0 dashboard](https://manage.auth0.com/), configure:

- **Allowed Callback URLs:** `http://localhost:3000/callback`
- **Allowed Logout URLs:** `http://localhost:3000`

### 6. Create `server.py`

```python
import os
from flask import Flask, redirect, render_template, session, url_for
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY")

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=os.getenv('AUTH0_CLIENT_ID'),
    client_secret=os.getenv('AUTH0_CLIENT_SECRET'),
    api_base_url=f"https://{os.getenv('AUTH0_DOMAIN')}",
    access_token_url=f"https://{os.getenv('AUTH0_DOMAIN')}/oauth/token",
    authorize_url=f"https://{os.getenv('AUTH0_DOMAIN')}/authorize",
    client_kwargs={'scope': 'openid profile email'},
)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=url_for('callback', _external=True))

@app.route('/callback')
def callback():
    token = auth0.authorize_access_token()
    userinfo = auth0.get('userinfo').json()
    session['user'] = userinfo
    return redirect('/dashboard')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    return render_template('dashboard.html', user=session['user'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(
        f"https://{os.getenv('AUTH0_DOMAIN')}/v2/logout?returnTo={url_for('home', _external=True)}&client_id={os.getenv('AUTH0_CLIENT_ID')}"
    )

@app.route("/protected")
def protected():
    user = session.get("user")
    if user is None:
        # Save current URL to return after login (optional)
        session["redirect_after_login"] = request.path
        return redirect(url_for("login"))
    return render_template("protected.html", user=user)

if __name__ == '__main__':
    app.run(debug=True, port=3000)
```

### 7. Create `templates/home.html`

```html
<!DOCTYPE html>
<html>
<head><title>Home</title></head>
<body>
  <h1>Welcome</h1>
  <a href="{{ url_for('login') }}">Login</a>
</body>
</html>
```

### 8. Create `templates/dashboard.html`

```html
<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
  <h1>Hello, {{ user.name }}</h1>
  <p>Email: {{ user.email }}</p>
  <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
```

### 9. Create `templates/protected.html`

```html
<!DOCTYPE html>
<html>
<head>
    <title>Protected Page</title>
</head>
<body>
    <h1>Welcome to the Protected Page</h1>
    <p>You are logged in as {{ user['userinfo']['email'] }}</p>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
```

### 10. Run the Application

```bash
python server.py
```

Visit: [http://localhost:3000](http://localhost:3000)


# 🎥 Video Link
[Watch on YouTube](https://drive.google.com/file/d/1ZdEWX-D8ly3vZmKJ9WoVyVmsr2rB36jU/view?usp=sharing)
