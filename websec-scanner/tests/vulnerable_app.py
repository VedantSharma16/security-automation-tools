"""A deliberately-misconfigured Flask app used only as an in-process scan
target for the test suite. It never talks to the network beyond localhost
and is not shipped/installed as part of the `websec` package.
"""

from __future__ import annotations

from flask import Flask, Response, request
from markupsafe import escape

GIT_CONFIG_BODY = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def home():
        html = """
        <html><body>
        <a href="/search?q=hello">search</a>
        <a href="/users?id=1">user</a>
        <form method="GET" action="/search">
            <input name="q" value="test">
        </form>
        </body></html>
        """
        resp = Response(html, mimetype="text/html")
        # Intentionally insecure: no Secure/HttpOnly/SameSite.
        resp.set_cookie("session_id", "abc123insecure")
        return resp

    @app.route("/secure")
    def secure():
        resp = Response("<html><body>secure page</body></html>", mimetype="text/html")
        resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "geolocation=()"
        resp.set_cookie("session_id", "abc123", httponly=True, samesite="Lax")
        return resp

    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        # Intentionally vulnerable: reflects `q` without escaping.
        return Response(f"<html><body>Results for: {q}</body></html>", mimetype="text/html")

    @app.route("/search-safe")
    def search_safe():
        q = request.args.get("q", "")
        return Response(f"<html><body>Results for: {escape(q)}</body></html>", mimetype="text/html")

    @app.route("/users")
    def users():
        user_id = request.args.get("id", "")
        if "'" in user_id:
            return Response(
                "Warning: mysqli_query(): You have an error in your SQL syntax; "
                f"check the manual near \"'{user_id}'\" at line 1",
                status=200,
                mimetype="text/plain",
            )
        return Response(f"<html><body>User {user_id}</body></html>", mimetype="text/html")

    @app.route("/.git/config")
    def git_config():
        return Response(GIT_CONFIG_BODY, mimetype="text/plain")

    @app.route("/robots.txt")
    def robots():
        return Response("User-agent: *\nDisallow: /admin\nDisallow: /backup\n", mimetype="text/plain")

    return app
