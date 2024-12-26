import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    db.execute("DELETE FROM stocks WHERE shares = 0")
    rows = db.execute(
        "SELECT symbol, SUM(shares) AS [shares] FROM stocks WHERE stocks_id=? GROUP BY symbol", session["user_id"])
    price = [float(lookup(row['symbol'])['price']) for row in rows]
    rows_and_prices = zip(rows, price)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    total = 0
    i = 0
    for row in rows:
        total = total + int(row['shares']) * int(price[i])
        i = i + 1
    total = total + cash[0]['cash']
    return render_template("index.html", rows_and_prices=rows_and_prices, cash=cash[0]['cash'], total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        user_id = session["user_id"]
        name = request.form.get("symbol")
        if not name:
            return apology("Missing symbol")
        shares = request.form.get("shares")
        try:
            if not shares or int(shares) <= 0:
                return apology("invalid share")
        except:
            return apology("invalid share")
        try:
            result = lookup(name)
            price = result["price"]
            symbol = result["symbol"]
        except:
            return apology("Invalid symbol")
        row = db.execute("SELECT cash FROM users WHERE id = (?)", user_id)
        cash = row[0]["cash"]
        cash = int(cash) - (int(price) * int(shares))
        if int(cash) < 0:
            return apology("Sorry not enough cash")
        old_shares = db.execute(
            "SELECT shares FROM stocks WHERE stocks_id = ? AND symbol = ?", user_id, symbol)
        try:
            new_shares = int(shares) + int(old_shares[0]["shares"])
            db.execute("UPDATE stocks SET shares = ? WHERE symbol = ? AND stocks_id = ?",
                       new_shares, symbol, user_id)
        except:
            db.execute("INSERT INTO stocks (stocks_id, symbol, shares) VALUES (?, ?, ?)",
                       user_id, symbol, shares)
        db.execute("INSERT INTO history (history_id, symbol, shares) VALUES (?, ?, ?)",
                   user_id, symbol, shares)
        db.execute("UPDATE users SET cash = ? WHERE id=?", cash, user_id)
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT * FROM history WHERE history_id=?", session["user_id"])
    price = [float(lookup(row['symbol'])['price']) for row in rows]
    rows_and_prices = zip(rows, price)
    return render_template("history.html", rows_and_prices=rows_and_prices)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        name = request.form.get("symbol")
        try:
            result = lookup(name)
            price = result["price"]
            symbol = result["symbol"]
        except:
            return apology("Invalid symbol")
        print(f"Symbol: {symbol}, Price: {price}")
        return render_template("quoted.html", symbol=symbol, price=price)
    else:
        return render_template("/quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        reg_username = request.form.get("username")
        reg_password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not reg_username:
            return apology("must provide username", 400)
        elif not reg_password:
            return apology("must provide password", 400)
        elif not confirmation:
            return apology("must provide confirmation", 400)
        elif confirmation != reg_password:
            return apology("password and confirmation does not match", 400)
        hash_password = generate_password_hash(reg_password, method='pbkdf2', salt_length=16)
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                       reg_username, hash_password)
        except ValueError:
            return apology("username is taken")
        return render_template("login.html")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        rows = db.execute(
            "SELECT symbol, SUM(shares) AS [shares] FROM stocks WHERE stocks_id = ? GROUP BY symbol", session["user_id"])
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        print(cash)
        name = request.form.get("symbol")
        if not name:
            return apology("Missing symbol")
        shares = request.form.get("shares")
        try:
            if not shares or int(shares) <= 0:
                return apology("Invalid share")
        except:
            return apology("Invalid share")
        for row in rows:
            if row['symbol'] == name:
                if int(row['shares']) < int(shares):
                    return apology("Not enough shares")
                else:
                    new_shares = int(row['shares']) - int(shares)
                    result = lookup(name)
                    price = result["price"]
                    new_cash = int(price) * int(shares) + int(cash[0]['cash'])
                    sold_shares = 0 - int(shares)
                    db.execute("UPDATE users SET cash = ? WHERE id =?",
                               new_cash, session["user_id"])
                    db.execute("update stocks set shares = ? WHERE stocks_id = ? AND symbol = ? ",
                               new_shares, session["user_id"], name)
                    db.execute("INSERT INTO history (history_id, symbol, shares) VALUES (?, ?, ?)",
                               session["user_id"], name, sold_shares)
        return redirect("/")
    else:
        rows = db.execute(
            "SELECT symbol FROM stocks WHERE stocks_id = ? GROUP BY symbol", session["user_id"])
        return render_template("sell.html", rows=rows)


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    """Register user"""
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")
        if not current_password:
            return apology("Must provide current password", 403)
        elif not new_password:
            return apology("Must provide a new password", 403)
        elif not confirmation:
            return apology("Must provide confirmation", 403)
        elif confirmation != new_password:
            return apology("Password and confirmation does not match", 403)
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if not check_password_hash(
                rows[0]["hash"], request.form.get("current_password")):
            return apology("Invalid password", 403)
        hash_password = generate_password_hash(new_password, method='pbkdf2', salt_length=16)
        db.execute("UPDATE users SET hash = ?", hash_password)
        return render_template("login.html")

    else:
        return render_template("change_password.html")
