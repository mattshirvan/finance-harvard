import os

from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from flask_migrate import Migrate
import re
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd
from decimal import Decimal
from re import sub

# Configure application
app = Flask(__name__)
app.secret_key = 'sneaky sneaky'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///finance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# password personal touch
PASSWORD = re.compile(r'^.*(?=.{8,10})(?=.*[a-zA-Z])(?=.*?[A-Z])(?=.*\d)[a-zA-Z0-9!@£$%^&*()_+={}?:~\[\]]+$')

# create database connection
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# create class for ORM
db.Model.metadata.reflect(db.engine)
class User(db.Model):
    __table__ = db.Model.metadata.tables["users"]


# create stock class
class Stock(db.Model):
    __table__ = db.Model.metadata.tables["stocks"]



# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    if 'user_id' not in session:
        flash("Please Login")
        return redirect("/login")

    stock = Stock.query.with_entities(Stock.symbol, func.sum(Stock.shares)).filter_by(user_id = session['user_id']).group_by(Stock.symbol).order_by("created_at").all()

    stocks = []
    for i in range(len(stock)):
        value = lookup(stock[i][0])
        data = {
            'symbol': value['symbol'],
            'name': value['name'],
            'shares': stock[i][1],
            'price': usd(value['price']),
            'total': usd(int(stock[i][1]) * float(value['price']))
        }

        stocks.append(data)

    return render_template("index.html", stocks = stocks)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "GET":
        return render_template("buy.html")

    if request.method == "POST":
        if not request.form.get("symbol"):
            flash("Please enter a valid symbol")
            return redirect("/buy")
        if not request.form.get("shares"):
            flash("Enter 1 or more shares to sell")
            return redirect("/buy")

        user = User.query.filter_by(id = session['user_id']).first()
        stock = lookup(request.form.get("symbol"))
        total = stock['price'] * int(request.form.get("shares"))
        new_stock = Stock(name = stock["name"], symbol = stock['symbol'], shares = request.form.get("shares"), price = usd(stock['price']), total = usd(total), user_id = session["user_id"])
        user.cash = int(user.cash) - total
        db.session.add(new_stock)
        db.session.commit()
        return redirect("/")

@app.route("/history")
@login_required
def history():
    if "user_id" not in session:
        return redirect("/")

    stocks = Stock.query.filter_by(user_id = session['user_id']).all()
    return render_template("history.html", stocks = stocks)


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
        # rows = db.execute("SELECT * FROM users WHERE username = :username",
        #                   username=request.form.get("username"))
        rows = User.query.filter_by(username = request.form.get('username')).all()
        print(rows)

        # Ensure username exists and password is correct
        if not rows or not check_password_hash(rows[0].hash, request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0].id
        session["cash"] = usd(rows[0].cash)
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
    # get quote if get method
    if "user_id" in session:
        if request.method == "GET":
            return render_template("quote.html")
        elif request.method == "POST":
            quote = lookup(request.form.get("symbol"))
            return render_template("quoted.html", quote = quote, price = usd(quote['price']))
    else:
        return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    # if landing on page
    if request.method == "GET":
        return render_template("register.html")

    # if posting to registration form
    elif request.method == "POST":
        if not request.form.get("username") or not request.form.get("password"):
            flash("Must provide a username and password")
            return redirect("/register")
        if User.query.filter_by(username = request.form.get("username")).all():
            flash("Username already taken")
            return redirect("/register")
        if not PASSWORD.match(request.form.get("password")):
            flash("Password must be a minimum of 6 charachters, a mix of uppercase & lowercase and include numbers & at least one special character")
            return redirect("/register")
        if re.search(r";|'|-", request.form.get("username")) or re.search(r";|'|-", request.form.get("password")) or re.search(r";|'|-", request.form.get("confirm")):
            flash("ILLEGAL!!!")
            return redirect("/register")
        if request.form.get("confirm") != request.form.get("password"):
            flash("Passwords must match")
            return redirect("/register")
        else:
            password = generate_password_hash(request.form.get("password"))
            new_user = User(username = request.form.get("username"), hash = password)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration Success!")
            return redirect("/login")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    # validate the user
    if "user_id" not in session:
        flash("Please Login")
        return redirect("/login")

    # if a get request
    if request.method == "GET":
        stocks = Stock.query.filter_by(user_id = session['user_id']).filter(Stock.shares > 0).all()
        return render_template("sell.html", stocks = stocks)

    # if a post request
    if request.method == "POST":
        # query database
        stocks = Stock.query.filter_by(user_id = session['user_id']).filter(Stock.shares > 0).filter_by(symbol = request.form.get("symbol")).group_by(Stock.symbol).all()

        # check if valid submission
        if not request.form.get("symbol"):
            flash("Please enter a valid symbol")
            return redirect("/sell")
        if request.form.get("symbol") not in stocks[0].symbol:
            flash("You do not have any shares of this stock")
            print(stocks[0].symbol)
            return redirect("/sell")
        if not request.form.get("shares"):
            flash("Enter 1 or more shares to sell")
            return redirect("/sell")

        if int(request.form.get("shares")) > stocks[0].shares:
            flash("You do not have enough shares")
            return redirect("/sell")

        else:
            value = lookup(stocks[0].symbol)
            stock_total = (int(request.form.get("shares")) * float(value['price']))
            print(request.form.get("symbol"), request.form.get("shares"))
            # stocks[0].shares = int(stocks[0].shares) - int(request.form.get("shares"))
            # stocks[0].total = usd(float(stock_total) - (int(request.form.get("shares")) * float(value['price'])))
            # stocks[0].users_who_sold_this_stock.shares = request.form.get("shares")
            # stocks[0].users_who_sold_this_stock.price = usd(float(value['price']))

            user = User.query.filter_by(id = session['user_id']).first()
            user.cash = int(user.cash) + stock_total

            sold = Stock(name = value["name"], symbol = value['symbol'], shares = (-int(request.form.get("shares"))), price = usd(float(value['price'])), total = ('-'+usd(stock_total)), user_id = session["user_id"])
            db.session.add(sold)
            db.session.commit()
            return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

if __name__ == "__main__":
    app.run(debug=True)
