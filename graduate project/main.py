from flask import Flask, render_template, flash, redirect, url_for, flash, request, jsonify
from flask_bootstrap import Bootstrap5
from forms import SignUpForm, LoginForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, current_user, LoginManager, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_ckeditor import CKEditor
from sqlalchemy.orm import relationship

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

login_manager = LoginManager(app)
login_manager.init_app

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy()
db.init_app(app)

class OwnBook(db.Model):
    __tablename__ = "ownbooks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250))
    author = db.Column(db.String(250))
    ISBN = db.Column(db.String(250))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
   
class WishBook(db.Model):
    __tablename__ = "wishbooks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250))
    author = db.Column(db.String(250))
    ISBN = db.Column(db.String(250))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # user = relationship('User', back_populates='wishbook')
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    wishbook = relationship('WishBook')
    ownhbook = relationship('OwnBook')
    


with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            flash("You've already signed up with taht email, log in instead!")
            return redirect(url_for("login"))
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8,
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('ownlist'))
    return render_template("signup.html", form=form, current_user=current_user)

@app.route("/login",methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('ownlist'))
    return render_template("login.html", form=form, current_user=current_user)

@app.route("/addown", methods=["GET", "POST"])
def addown():
    if request.method == "POST":

        new_book = OwnBook(
            title=request.form["title"],
            author=request.form["author"],
            ISBN=request.form["ISBN"],   
            user_id = current_user.id
        )
        db.session.add(new_book)
        db.session.commit()
        return redirect(url_for('ownlist'))
    return render_template("addown.html", current_user=current_user)

@app.route("/addwish", methods=["GET", "POST"])
def addwish():
    if request.method == "POST":

        new_book = WishBook(
            title=request.form["title"],
            author=request.form["author"],
            ISBN=request.form["ISBN"], 
            user_id = current_user.id
        )
        
        db.session.add(new_book)
        db.session.commit()
        return redirect(url_for('wishlist'))
    return render_template("addwish.html", current_user=current_user)



@app.route('/ownlist')
def ownlist():
    result = db.session.execute(db.select(OwnBook).filter_by(user_id=current_user.id).order_by(OwnBook.title))
    all_books = result.scalars()
    return render_template("ownlist.html", books=all_books)

@app.route('/wishlist')
def wishlist():
    result = db.session.execute(db.select(WishBook).filter_by(user_id=current_user.id).order_by(WishBook.title))
    all_books = result.scalars()
    return render_template("wishlist.html", books=all_books)

@app.route("/deleteown")
def deleteown():
    book_id = request.args.get('id')
    book_to_delete = db.get_or_404(OwnBook, book_id)
    db.session.delete(book_to_delete)
    db.session.commit()
    return redirect(url_for('ownlist'))

@app.route("/deletewish")
def deletewish():
    book_id = request.args.get('id')
    book_to_delete = db.get_or_404(WishBook, book_id)
    db.session.delete(book_to_delete)
    db.session.commit()
    return redirect(url_for('wishlist'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# @app.route('/search', methods=["POST"])
# def search():
#     return jsonify({"result" : 1})

if __name__ == '__main__':
    app.run(debug=True)

    