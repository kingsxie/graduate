from flask import Flask, render_template, flash, redirect, url_for, flash, request, jsonify
from flask_bootstrap import Bootstrap5
from forms import SignUpForm, LoginForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, current_user, LoginManager, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_ckeditor import CKEditor
from sqlalchemy.orm import relationship, aliased

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

@app.route('/search')
def search():
    OwnBookAlias1 = aliased(OwnBook)
    WishBookAlias1 = aliased(WishBook)
    UserAlias1 = aliased(User)
    OwnBookAlias2 = aliased(OwnBook)
    WishBookAlias2 = aliased(WishBook)
    UserAlias2 = aliased(User)

    current_user_id = current_user.id

    matches = db.session.query(
        UserAlias1.name.label("owner1_name"), 
        OwnBookAlias1.title.label("owned1_title"),
        WishBookAlias1.title.label("wish1_title"),
        UserAlias2.name.label("owner2_name"), 
        OwnBookAlias2.title.label("owned2_title"),
        WishBookAlias2.title.label("wish2_title")
    )\
    .join(OwnBookAlias1, OwnBookAlias1.user_id == UserAlias1.id)\
    .join(WishBookAlias1, OwnBookAlias1.ISBN == WishBookAlias1.ISBN)\
    .join(OwnBookAlias2, OwnBookAlias2.user_id == UserAlias2.id)\
    .join(WishBookAlias2, OwnBookAlias2.ISBN == WishBookAlias2.ISBN)\
    .filter(OwnBookAlias1.user_id != WishBookAlias1.user_id)\
    .filter(OwnBookAlias2.user_id != WishBookAlias2.user_id)\
    .filter(OwnBookAlias1.user_id == WishBookAlias2.user_id)\
    .filter(OwnBookAlias2.user_id == WishBookAlias1.user_id)\
    .filter(UserAlias1.id == current_user_id)\
    .filter(UserAlias2.id != current_user_id).all()

    return render_template("search.html", matches=matches)

@app.route('/searchagain')
def searchagain():
    potential_matches = fetch_potential_matches()
    cycles = find_three_way_cycles(potential_matches)
    
    # For demonstration, convert cycle matches to a more readable format
    readable_cycles = [{
        'user_a': User.query.get(cycle[0].owner_id).name,
        'user_a_book': cycle[0].owned_title,
        'user_a_book_isbn': cycle[0].owned_ISBN,  # Include ISBN
        'user_b': User.query.get(cycle[1].owner_id).name,
        'user_b_book': cycle[1].owned_title,
        'user_b_book_isbn': cycle[1].owned_ISBN,  # Include ISBN
        'user_c': User.query.get(cycle[2].owner_id).name,
        'user_c_book': cycle[2].owned_title,
        'user_c_book_isbn': cycle[2].owned_ISBN,  # Include ISBN
    } for cycle in cycles]
    print(readable_cycles)
    return render_template("searchagain.html", cycles=readable_cycles)

def fetch_potential_matches():
    # Fetch books that are both owned and wished for by different users
    potential_matches = db.session.query(
        OwnBook.user_id.label("owner_id"),
        OwnBook.title.label("owned_title"),
        OwnBook.ISBN.label("owned_ISBN"),
        WishBook.user_id.label("wisher_id"),
        WishBook.ISBN.label("wished_ISBN")
    ).join(WishBook, OwnBook.ISBN == WishBook.ISBN).filter(OwnBook.user_id != WishBook.user_id).all()
    
    return potential_matches

def find_three_way_cycles(potential_matches):
    # This is a naive approach to illustrate the concept
    cycles = []
    
    for match_a in potential_matches:
        for match_b in [m for m in potential_matches if m.wisher_id == match_a.owner_id]:
            for match_c in [m for m in potential_matches if m.wisher_id == match_b.owner_id and m.owner_id == match_a.wisher_id]:
                # Found a cycle
                if current_user.id == match_a.owner_id:
                    cycles.append((match_a, match_b, match_c))
    return cycles
if __name__ == '__main__':
    app.run(debug=True)

    