"""Project Flask Newsfeed: Emily Cleveland"""
#Corey Schafer's videos
#Standard library imports
from datetime import datetime
import math
from os import environ as env
from urllib.parse import quote_plus, urlencode


# Related third-party imports
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, request, jsonify, render_template, url_for, flash, redirect, session
from flask_bcrypt import Bcrypt
from flask_caching import Cache
from flask_migrate import Migrate  # Import Flask-Migrate
from flask_sqlalchemy import SQLAlchemy
import requests
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import func

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)


app = Flask(__name__)
oauth = OAuth(app)
app.secret_key = env.get("APP_SECRET_KEY")
app.config['SECRET_KEY'] = '74fd3ca6ea5e4931545c6a2667c366f1'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

app.config['CACHE_TYPE'] = 'simple'  # caching type
cache = Cache(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate
bcrypt = Bcrypt(app)

HACKERNEWS_TOP_STORIES_URL = "https://hacker-news.firebaseio.com/v0/topstories.json?print=pretty"
HACKERNEWS_ITEM_URL = "https://hacker-news.firebaseio.com/v0/item/"

ADMIN = ["example@gmail.com", "12345@gmail.com"] #change to your email to be admin

#create models
"""need for calculating likes and dislikes/ net likes"""
class Like(db.Model):
    """likes in the database"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Dislike(db.Model):
    """dislikes in the database"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

#Users and Posts
class User(db.Model):
    """users in the database"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    #password = db.Column(db.String(60), nullable=False)
    sub = db.Column(db.String(255), unique=True, nullable=True)
    posts = db.relationship('Post', backref='author', lazy=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    likes = db.relationship('Like', backref='user', lazy=True)
    dislikes = db.relationship('Dislike', backref='user', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

class Post(db.Model):
    """posts in the database"""
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(140))
    by = db.Column(db.String(140))
    descendants = db.Column(db.Integer)
    kids = db.Column(db.JSON)
    score = db.Column(db.Integer, default=0) #total count
    title = db.Column(db.String(140))
    url = db.Column(db.String(500))
    time = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    likes = db.relationship('Like', backref='post', lazy='dynamic')
    dislikes = db.relationship('Dislike', backref='post', lazy='dynamic')

    def __repr__(self):
        return f"Post('{self.id}', '{self.type}','{self.by}','{self.title}', '{self.url}', '{self.time}')"


#Auth0
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

@app.route("/")
@app.route("/home")
def home():
    """home display for newsfeed with posts sorted by time then likes"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    posts_with_net_likes, pagination_info = get_posts(page=page, per_page=per_page)
    return render_template("home.html", title='Home', session=session.get('user'),
                           posts=posts_with_net_likes,
                           pagination_info=pagination_info)


def get_posts(page=1, per_page=10):
    """gets 30 top news stories from hacknews"""
    with requests.Session() as s:
        top_story_ids = s.get(HACKERNEWS_TOP_STORIES_URL).json()[:30]  # Get top 30 stories
        for story_id in top_story_ids:
            if not Post.query.filter_by(id=story_id).first():
                story_data = fetch_story_data(story_id, s)
                save_to_database(story_data)
    
    # ordered by the time of the post then net likes 
    posts_with_net_likes = db.session.query(
        Post.id,
        Post.type,
        Post.by,
        Post.title,
        Post.url,
        Post.time,
        Post.user_id,
        (func.count(Like.id) - func.count(Dislike.id)).label('net_likes')
    ).outerjoin(Like, Post.id == Like.post_id) \
     .outerjoin(Dislike, Post.id == Dislike.post_id) \
     .group_by(Post.id) \
     .order_by(Post.time.desc(), 'net_likes').all()

    # Paginate the results manually as `paginate` is not available for raw queries
    paginated_posts = posts_with_net_likes[(page-1)*per_page : page*per_page]

    # Create a dictionary to mimic the structure of the paginate object
    total_posts = len(posts_with_net_likes)
    total_pages = math.ceil(total_posts / per_page)
    pagination_info = {
        'total': total_posts,
        'per_page': per_page,
        'page': page,
        'total_pages': total_pages
    }

    # Implement pagination for the posts
    start = (page - 1) * per_page
    end = start + per_page
    paginated_posts = posts_with_net_likes[start:end]


    return paginated_posts, pagination_info

def fetch_story_data(story_id, session):
    """gets story id"""
    story_url = HACKERNEWS_ITEM_URL + f"{story_id}.json"
    story_data = session.get(story_url).json()
    return story_data

def save_to_database(story):
    """saves to sqlite"""
    if not story:
        return
    
    existing_post = Post.query.filter_by(id=story['id']).first()
    if not existing_post:
        # Create a new post with the story data
        user_id = User.query.first().id if User.query.first() else None  
        # Assign to the first user, if exists
        new_post = Post(
            id=story['id'],
            type=story.get('type'),
            by=story.get('by'),
            title=story.get('title'),
            url=story.get('url'),
            time=datetime.fromtimestamp(story.get('time')),
            user_id=user_id
        )
        db.session.add(new_post)
        db.session.commit()

#change eventually
@app.route("/api/newsfeed")
def api_newsfeed():
    """used for the curl command for getting the json"""
    page = request.args.get('page', 1, type=int)  # Default to first page
    per_page = request.args.get('per_page', 10, type=int)  # Default to 10 items per page

    # Fetch paginated posts
    paginated_posts = Post.query.order_by(Post.time.desc()).paginate(page=page, 
                                                                     per_page=per_page, 
                                                                     error_out=False)

    posts_json = [{
        'id': post.id,
        'type': post.type,
        'by': post.by,
        'title': post.title,
        'url': post.url,
        'time': post.time.isoformat(),
        'user_id': post.user_id
    } for post in paginated_posts.items]

    return jsonify({
        'posts': posts_json,
        'total': paginated_posts.total,
        'pages': paginated_posts.pages,
        'current_page': page
    })


@app.route("/newsfeed")
def newsfeed():
    """Same feed as home that displays paginated posts by time then likes"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    posts_with_net_likes, pagination_info = get_posts(page=page, per_page=per_page)
    
    return render_template("newsfeed.html", title='Newsfeed', session=session.get('user'), 
                           posts=posts_with_net_likes,
                           pagination_info=pagination_info)

#follow the Auth0 tutorial
@app.route("/register")
def register():
    """redirects to the auth0 page; code from Auth0 website"""
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True),
        screen_hint="signup"
        )

@app.route("/login")
def login():
    # Redirect to Auth0 login page; code from Auth0 website
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    """code from Auth0 website; also has set admin"""
    token = oauth.auth0.authorize_access_token()
    USER_URL = "https://" + env.get("AUTH0_DOMAIN") + "/userinfo"
    resp = oauth.auth0.get(USER_URL).json()

    user_email = resp.get("email")
    user_sub = resp.get("sub")

    # Check if user exists in the database
    existing_user = User.query.filter_by(sub=user_sub).first()

    try:
        if not existing_user:
            # if the user is 'elc36118@gmail.com' then admin
            # place your email here to be admin
            is_admin = user_email in ADMIN

            # Create a new user
            new_user = User(
                username=resp.get("name", ""),
                email=user_email,
                sub=user_sub, 
                is_admin=is_admin
            )
            db.session.add(new_user)
            db.session.commit()
            session["user"] = {"sub": user_sub, "is_admin": is_admin}
        else:
            # Update existing user's admin status if email matches
            if user_email in ADMIN:
                existing_user.is_admin = True
                db.session.commit()

            session["user"] = {"sub": existing_user.sub, "is_admin": existing_user.is_admin}

    except IntegrityError:
        db.session.rollback()
        flash('An account with this email already exists.', 'error')
        return redirect(url_for('login'))

    return redirect(url_for('home'))

@app.route("/admin")
def admin_dashboard():
    """runs once is_admin is true for the correct email"""
    if not session.get('user') or not session['user'].get('is_admin'):
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('home'))

#get all users and posts
    users = User.query.all()
    posts = Post.query.all()
    
    return render_template('admin_dashboard.html',
                           title='Admin Dashboard', 
                           users=users, posts=posts)

@app.route('/admin/delete_news/<int:post_id>', methods=['POST'])
def delete_news(post_id):
    # Check if user is logged in or is admin
    if not session.get('user') or not session['user'].get('is_admin'):
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('home'))

    post_to_delete = Post.query.get_or_404(post_id)
    Like.query.filter_by(post_id=post_id).delete()
    Dislike.query.filter_by(post_id=post_id).delete()
    db.session.delete(post_to_delete)
    db.session.commit()
    flash('News item and related likes/dislikes have been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

#delete user
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    """deletes user and likes if admin"""
    if not session.get('user') or not session['user'].get('is_admin'):
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('home'))

    user_to_delete = User.query.get_or_404(user_id)
    Like.query.filter_by(user_id=user_id).delete()
    Dislike.query.filter_by(user_id=user_id).delete()
    db.session.delete(user_to_delete)
    db.session.commit()
    flash('User and related likes/dislikes have been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route("/logout")
def logout():
    """tells the auth0 route to logout"""
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

@app.route("/profile")
def profile():
    """displays the profile page and if admin, provides a link to the admin dash"""
    user_info = session.get("user")  # user info is stored in session after login
    if user_info:
         # Get the user's unique sub from the user info
        user_sub = user_info.get("sub")
        # Query the database for the user's data
        user = User.query.filter_by(sub=user_sub).first()
        if user:
            return render_template('profile.html', title='Profile', user=user)
        else:
            session.clear()
            flash("User not found in the database.", "warning")
            return redirect(url_for('login'))
    else:
        flash("You are not logged in.", "warning")
        return redirect(url_for('login'))

@app.route('/like_post/<int:post_id>', methods=['POST'])
def like_post(post_id):
    """likes if logged in as a user"""
    if 'user' not in session:
        flash('You must be logged in to like posts.', 'danger')
        return redirect(url_for('login'))
    user_sub = session['user']['sub']
    user = User.query.filter_by(sub=user_sub).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('home'))

    existing_like = Like.query.filter_by(user_id=user.id, post_id=post_id).first()
    if existing_like:
        flash('You have already liked this post.', 'info')
    else:
        new_like = Like(user_id=user.id, post_id=post_id)
        db.session.add(new_like)
        db.session.commit()
        flash('Post liked!', 'success')

    return redirect(request.referrer or url_for('home'))

@app.route('/dislike_post/<int:post_id>', methods=['POST'])
def dislike_post(post_id):
    """Undoes a like if logged in as a user"""
    # Check if user is logged in
    if 'user' not in session:
        flash('You must be logged in to unlike posts.', 'danger')
        return redirect(url_for('login'))
    
    user_sub = session['user']['sub']
    user = User.query.filter_by(sub=user_sub).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('home'))

    # Check for existing like and remove it
    existing_like = Like.query.filter_by(user_id=user.id, post_id=post_id).first()
    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        flash('You have unliked this post.', 'info')
    else:
        flash('You have not liked this post.', 'info')

    return redirect(request.referrer or url_for('home'))

@app.route("/liked_posts")
def liked_posts():
    if 'user' not in session:
        flash('You must be logged in to view liked posts.', 'danger')
        return redirect(url_for('login'))

    user_sub = session['user']['sub']
    user = User.query.filter_by(sub=user_sub).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('home'))

    liked_posts = db.session.query(
        Post,
        (func.count(Like.id) - func.count(Dislike.id)).label('net_likes')
    ).join(Like, Post.id == Like.post_id) \
     .outerjoin(Dislike, Post.id == Dislike.post_id) \
     .filter(Like.user_id == user.id) \
     .group_by(Post.id) \
     .all()

    return render_template("liked_posts.html", posts=liked_posts)

@app.route('/search', methods=['GET'])
def search_results():
    query = request.args.get('q')
    if not query:
        return redirect(url_for('home'))

    # Search logic
    results = Post.query.filter(
        (Post.title.ilike(f'%{query}%')) |
        (Post.by.ilike(f'%{query}%'))
    ).all()

    return render_template('search_results.html', posts=results)



if __name__ == '__main__':
    app.run(debug=True)
