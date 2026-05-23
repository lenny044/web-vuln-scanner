from flask import Flask, request, redirect

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <html>
    <body>
        <h2>Login</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username"><br><br>
            <input type="password" name="password" placeholder="Password"><br><br>
            <input type="submit" value="Login">
        </form>

        <h2>Search</h2>
        <form method="GET" action="/search">
            <input type="text" name="q" placeholder="Search...">
            <input type="submit" value="Search">
        </form>
    </body>
    </html>
    """

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    return f"<p>Logged in as: {username}</p>"

@app.route("/search")
def search():
    query = request.args.get("q", "")
    return f"<p>Search results for: {query}</p>"

@app.route("/redirect")
def open_redirect():
    url = request.args.get("url", "/")
    return redirect(url)

if __name__ == "__main__":
    app.run(debug=True, port=5000)