from flask import Flask, render_template, redirect, url_for, flash, request, g, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CommentForm
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import DataRequired,Email
from functools import wraps

Base = declarative_base()
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
##CONFIGURE TABLES


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey('user.id'))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    parent = relationship("User", back_populates="posts")
    comments = relationship("Comments", back_populates="parent_post")




class User(UserMixin, db.Model, Base):

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = relationship("BlogPost", back_populates = "author")
    comments = relationship("Comments", back_populates = "author")



class Comments(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200))
    author = relationship("User", back_populates="comments")
    author_id = db.Column(Integer, ForeignKey("user.id"))
    post_id = db.Column(Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates= "comments")

db.create_all()
class MyForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField("Password")
    submit = SubmitField(label="Log In")

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in= current_user.is_authenticated)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = MyForm()
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        print(password, type(password))
        password_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
        user = db.session.query(User).filter_by(email=email).first()
        if user:
            flash("Email already registered, please log in.")
        else:
            new_user = User(email=email, name=name, password=password_hash)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST","GET"])
def login():
    form = MyForm()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        password_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                return password_hash
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    if current_user:
        logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to log in to comment")
            return redirect(url_for("login"))
        else:
            new_comment = Comments(text=comment_form.content.data, author=current_user, parent_post=requested_post)
            db.session.add(new_comment)
            db.session.commit()
    return render_template("post.html", post=requested_post, form=comment_form, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
