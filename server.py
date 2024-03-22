import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from flask_login import login_user, UserMixin, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from markupsafe import Markup
from sqlalchemy import Integer, Text, String, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, URLField, SubmitField, EmailField, PasswordField
from wtforms.validators import DataRequired, Length

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = os.environ.get("SEC_KEY")

csrf = CSRFProtect(app)
Bootstrap(app)
ckeditor = CKEditor(app)
login_manager = LoginManager()
login_manager.init_app(app)

my_email = os.environ.get("MAIN_EMAIL")
password = os.environ.get("MAIN_EMAIL_PASS")
email = os.environ.get("MAIN_EMAIL")


def admin_only(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        if (current_user.is_authenticated and current_user.id != 1) or (not current_user.is_authenticated):
            return abort(403)
        return f(*args, **kwargs)

    return decorator_function


@app.context_processor
def inject_logged_in():
    def is_logged_in():
        return current_user.is_authenticated

    return dict(is_logged_in=is_logged_in)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


class Base(DeclarativeBase):
    pass


app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author = relationship("User", back_populates="posts")
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'))
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'))
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    author = relationship("User", back_populates="comments")
    parent_post = relationship("BlogPost", back_populates="comments")
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    posts = relationship("BlogPost")
    comments = relationship("Comment", back_populates="author")

    def __init__(self, email, password, name, posts=None, comments=None):
        self.email = email
        self.password = password
        self.name = name
        self.posts = posts or []
        self.comments = comments or []

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


def posts_list():
    get_posts = db.session.execute(db.select(BlogPost))
    posts = get_posts.scalars().all()
    return posts


def comments_list(post_id):
    comments = db.session.execute(db.select(BlogPost).where(BlogPost.id == post_id)).scalars().all()
    return comments


class AddPostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = URLField("Blog Image URL", validators=[DataRequired()])
    body = CKEditorField("Blog Content", validators=[DataRequired()], _translations='en')
    submit = SubmitField("Submit Post", render_kw={"class": "btn-primary btn-sm mt-3"})


class AddCommentForm(FlaskForm):
    body = CKEditorField("Blog Content", validators=[DataRequired()], _translations='en')
    submit = SubmitField("Leave Comment", render_kw={"class": "btn-primary btn-sm mt-3"})


class RegisterForm(FlaskForm):
    name = StringField("Your Name", validators=[DataRequired(), Length(min=2)])
    email = EmailField("Your Email", validators=[DataRequired()])
    password = PasswordField("Your Password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField("Register", render_kw={"class": "btn-primary btn-sm mt-3"})


class LoginForm(FlaskForm):
    email = EmailField("Your Email", validators=[DataRequired()])
    password = PasswordField("Your Password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField("Login", render_kw={"class": "btn-primary btn-sm mt-3"})


@app.context_processor
def inject_year():
    current_year = datetime.now().year
    return {'current_year': current_year}


@app.route("/")
def build_main():
    authenticated = current_user.is_authenticated
    posts = posts_list()
    return render_template("index.html", posts=posts, authenticated=authenticated)


@app.route("/about")
def build_about():
    return render_template("about.html")


@app.route("/contact", methods=["POST", "GET"])
def build_contact():
    if request.method == "POST":
        try:
            name = request.form["name"].strip()
            e_mail = request.form["email"].strip()
            phone = request.form["phone"].strip()
            message = request.form["message"].strip()
            message_content = f"Name: {name}\nEmail: {e_mail}\nPhone: {phone}\nMessage: {message}"

            msg = MIMEMultipart()
            msg["From"] = e_mail
            msg["To"] = my_email
            msg["Subject"] = e_mail

            text = MIMEText(message_content, "plain")
            msg.attach(text)

            with smtplib.SMTP("smtp.gmail.com") as connection:
                connection.starttls()
                connection.login(user=my_email, password=password)
                connection.send_message(msg)

            return render_template("thank-you.html", title="Form submission successful!",
                                   description="We received your form and will answer soon")
        except smtplib.SMTPException as e:
            # Handle SMTP-related exceptions
            return render_template("contact.html", title="Error sending email: " + str(e),
                                   description="Failed to send your email, Please try again later", error=True)
        except Exception as e:
            # Handle other exceptions
            return render_template("contact.html", title="An error occurred: " + str(e),
                                   description="We have a technical issues. Please try again later", error=True)

    return render_template("contact.html")


@app.route("/posts/post/<int:post_id>", methods=["GET", "POST"])
def build_post(post_id):
    authenticated = current_user.is_authenticated
    form = AddCommentForm()
    posts = posts_list()
    users = db.session.execute(db.select(User)).scalars().all()
    comments = comments_list(post_id)
    translator = Markup
    return render_template("post.html", posts=posts, id=post_id, translator=translator, authenticated=authenticated,
                           form=form, comments=comments, users=users)


@app.route("/new-post", methods=["GET", "POST"])
@login_required
def create_post():
    form = AddPostForm()
    validation = form.validate_on_submit()
    if validation:
        new_post = BlogPost(
            title=form.title.data.capitalize(),
            subtitle=form.subtitle.data.capitalize(),
            date=datetime.now().strftime("%B %d, %Y"),
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        flash("New Post Added")
        return redirect(url_for('build_main'))

    return render_template("add.html", form=form, is_edit=False)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    db_post = db.get_or_404(BlogPost, post_id)
    form = AddPostForm(obj=db_post)

    if form.validate_on_submit():
        if form.data != form.data.get("_obj"):  # Check if the form data has changed
            form.populate_obj(db_post)  # Update fields of db_post with form data
            db.session.commit()  # Save changes to the database
            flash("Fields have been changed!", "success")
        else:
            flash("No changes were made.", "info")
        return redirect(url_for("build_post", post_id=post_id))

    return render_template("add.html", form=form, is_edit=True)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post = db.get_or_404(BlogPost, post_id)

    if post:
        db.session.delete(post)
        db.session.commit()
        flash("Post Deleted Successfully")
        return redirect(url_for('build_main'))
    else:
        flash("Post not found")
        return redirect(url_for('build_main'))


@app.route("/new-comment/<int:post_id>", methods=["GET", "POST"])
@login_required
def create_comment(post_id):
    form = AddCommentForm()
    validation = form.validate_on_submit()
    if validation:
        new_comment = Comment(
            text=form.body.data,
            date=datetime.now().strftime("%B %d %Y, %H:%M:%S"),
            author_id=current_user.id,
            post_id=post_id
        )
        db.session.add(new_comment)
        db.session.commit()
        flash("New Comment Added")
        return redirect(url_for('build_post', post_id=post_id))


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    password = request.form.get("password")
    email = request.form.get("email")

    if request.method == "POST" and form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()

        if user:
            check_password = check_password_hash(user.password, password)
            if check_password:

                login_user(user, remember=True)
                flash("USER AUTHORIZED IN THE SYSTEM")
                return render_template("user.html", user=current_user.to_dict())
            else:
                flash("Wrong Password")
                return render_template("login.html", form=form, message="Please check your password")
        else:
            flash("We don't find you in our system... Redirecting to registration...")
            return render_template("login.html", form=form,
                                   message=("You are not registered in our system. Please check your data "
                                            "or follow to Registration"))

    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    form_email = request.form.get("email")

    if request.method == "POST" and form.validate_on_submit():
        user = User.query.filter_by(email=form_email).first()

        if user:
            flash("You Already Have An Account... Redirecting To Login")
            return redirect(url_for("login"))
        new_user = User(
            name=request.form.get("name"),
            email=form_email,
            password=generate_password_hash(password=request.form.get("password"), method="pbkdf2", salt_length=8)
        )

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash("New User Has Added")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return render_template("index.html")


@app.route("/user")
@login_required
def user():
    return render_template("user.html", current_user=current_user, user=current_user.to_dict())


@app.route('/authors/<author_name>')
def user_profile(author_name):
    user = User.query.filter_by(name=author_name.capitalize()).first()
    translator = Markup

    if user:
        posts = BlogPost.query.filter_by(author=user).all()
        return render_template("user.html", user=user.to_dict(), posts=posts, translator=translator)
    else:
        return "Author not found"


if __name__ == "__main__":
    app.run(port=3000, debug=True)
