import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
import usbguard_adapter as ug

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")  # change before real use

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == ADMIN_USER and request.form["password"] == ADMIN_PASS:
            session["user"] = ADMIN_USER
            return redirect(url_for("devices"))
        flash("Wrong username or password")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@app.route("/devices")
@login_required
def devices():
    devs = ug.list_devices()
    stats = {"total": len(devs),
             "allowed": sum(d["status"] == "allowed" for d in devs),
             "pending": sum(d["status"] == "pending" for d in devs),
             "blocked": sum(d["status"] == "blocked" for d in devs)}
    return render_template("devices.html", devices=devs, stats=stats, page="devices", mode=ug.MODE)

@app.route("/trusted")
@login_required
def trusted():
    return render_template("trusted.html", devices=ug.trusted_devices(), page="trusted", mode=ug.MODE)

@app.route("/alerts")
@login_required
def alerts():
    return render_template("alerts.html", alerts=ug.get_alerts(), page="alerts", mode=ug.MODE)

@app.route("/allow/<dev_id>", methods=["POST"])
@login_required
def allow(dev_id):
    flash("Device allowed" if ug.set_status(dev_id, "allowed") else "Could not allow device")
    return redirect(request.referrer or url_for("devices"))

@app.route("/block/<dev_id>", methods=["POST"])
@login_required
def block(dev_id):
    flash("Device blocked" if ug.set_status(dev_id, "blocked") else "Could not block device")
    return redirect(request.referrer or url_for("devices"))

if __name__ == "__main__":
    app.run(debug=True)
