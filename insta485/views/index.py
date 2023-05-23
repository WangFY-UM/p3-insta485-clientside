"""
Insta485 index (main) view.

URLs include:
/
"""

import hashlib
import pathlib
import uuid
import os
import arrow

import flask
from flask import session, render_template, redirect, abort

import insta485


@insta485.app.route('/')
def show_index():
    """Display / route."""
    connection = insta485.model.get_db()

    if "username" not in flask.session:
        return flask.redirect("/accounts/login/")

    logname = flask.session["username"]
    cur = connection.execute(
        "SELECT username, fullname FROM users WHERE username != ?", (logname,)
    )
    users = cur.fetchall()

    cur = connection.execute(
        """
        SELECT * FROM posts WHERE owner = ?
        UNION
        SELECT posts.* FROM posts
        INNER JOIN following ON posts.owner = following.username2
        WHERE following.username1 = ?
        ORDER BY created DESC
        """,
        (logname, logname)
    )
    all_posts = cur.fetchall()

    for post in all_posts:
        present = arrow.now()
        post_time = arrow.get(post["created"], 'YYYY-MM-DD HH:mm:ss')
        post["created"] = post_time.humanize(present)
        cur = connection.execute(
            "SELECT filename FROM users WHERE username = ?", (post["owner"],)
        )
        post["profile"] = cur.fetchone()["filename"]
        post["num_likes"] = get_num_likes(post["postid"])
        post["liked"] = get_if_liked(logname, post["postid"])
        post["comments"] = get_comments(post["postid"])

    context = {"logname": logname, "users": users, "posts": all_posts}
    return flask.render_template("index.html", **context)


@insta485.app.route("/accounts/", methods=['POST'])
def show_accounts():
    """Intermediate page."""
    connection = insta485.model.get_db()
    operation = flask.request.form.get("operation")
    target = flask.request.args.get("target", "/")
    if operation == "login":
        username = flask.request.form.get("username")
        password = flask.request.form.get("password")

        if not username or not password:
            flask.abort(400)

        if not if_valid_password(username, password):
            flask.abort(403)

        flask.session["username"] = username

    elif operation == "create":
        create_account(connection)

    elif operation == "logout":
        flask.session.pop("username", None)
        return flask.redirect("/accounts/login/")

    elif operation == "delete":
        delete_account(connection)

    elif operation == "edit_account":
        edit_account(connection)

    else:  # operation == "update_password"
        update_password(connection)

    return flask.redirect(target)


def create_account(connection):
    """Create account."""
    username = flask.request.form.get("username")
    if connection.execute(
            "SELECT username FROM users WHERE username = ?",
            (username,)
            ).fetchone():
        flask.abort(409)

    password_db_string = encrypt_password(
        uuid.uuid4().hex, flask.request.form.get("password"))
    uploaded_file = flask.request.files.get("file")
    filename = uploaded_file.filename
    stem = uuid.uuid4().hex
    suffix = pathlib.Path(filename).suffix.lower()
    uuid_basename = f"{stem}{suffix}"

    path = insta485.app.config["UPLOAD_FOLDER"] / uuid_basename
    uploaded_file.save(path)

    connection.execute(
        """
        INSERT INTO users (username, fullname, email, filename, password)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            flask.request.form.get("username"),
            flask.request.form.get("fullname"),
            flask.request.form.get("email"),
            uuid_basename,
            password_db_string
        )
    )
    # auto login the user after create a user file
    flask.session["username"] = username


def delete_account(connection):
    """Delete account."""
    # there is no username from the form
    # username = flask.request.form.get("username")
    # use the current session username
    username = flask.session["username"]

    if not connection.execute(
            "SELECT username FROM users WHERE username = ?", (username,)
            ).fetchone():
        flask.abort(404)

    # delete the posts that user makes ----
    posts_query = connection.execute(
        "SELECT filename "
        "FROM posts "
        "WHERE owner = ?",
        (username, )
    )
    posts = posts_query.fetchall()

    for post in posts:
        path = insta485.app.config["UPLOAD_FOLDER"]/post["filename"]
        os.remove(path)
    # delete the posts that user makes ----

    # delete the profile picture of the user ----
    users_query = connection.execute(
        "SELECT filename "
        "FROM users "
        "WHERE username = ?",
        (username, )
    )
    users = users_query.fetchall()
    for user in users:
        path = insta485.app.config["UPLOAD_FOLDER"]/user["filename"]
        os.remove(path)
    # delete the profile picture of the user ----
    connection.execute("DELETE FROM users WHERE username = ?", (username,))
    flask.session.pop("username", None)


def edit_account(connection):
    """Edit account."""
    if not flask.session.get("username"):
        flask.abort(403)
    if ("fullname" not in flask.request.form
            or "email" not in flask.request.form):
        flask.abort(400)

    connection.execute(
        "UPDATE users SET fullname = ?, email = ? WHERE username = ?",
        (
            flask.request.form.get("fullname"),
            flask.request.form.get("email"),
            flask.session.get("username")
        )
    )

    if "file" in flask.request.files:
        uploaded_file = flask.request.files.get("file")
        filename = uploaded_file.filename
        if filename != '':
            stem = uuid.uuid4().hex
            suffix = pathlib.Path(filename).suffix.lower()
            uuid_basename = f"{stem}{suffix}"

            cur = connection.execute(
                "SELECT filename FROM users WHERE username = ?",
                (flask.session.get("username"), )
            )
            filename = cur.fetchone()["filename"]

            path = insta485.app.config["UPLOAD_FOLDER"]/filename
            os.remove(path)

            connection.execute(
                "UPDATE users SET filename = ? WHERE username = ?",
                (uuid_basename, flask.session.get("username"))
            )
    # DO NOT logout the user after edit
    # flask.session.pop("username", None)


def update_password(connection):
    """Update password."""
    if not flask.session.get("username"):
        flask.abort(403)
    if (
            "password" not in flask.request.form or
            "new_password1" not in flask.request.form or
            "new_password2" not in flask.request.form
            ):
        flask.abort(400)
    if not if_valid_password(flask.session.get("username"),
                             flask.request.form.get("password")):
        flask.abort(403)
    if (flask.request.form.get("new_password1")
            != flask.request.form.get("new_password2")):
        flask.abort(401)

    algorithm = 'sha512'
    salt = uuid.uuid4().hex
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + flask.request.form.get("new_password1")
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])

    connection.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (password_db_string, flask.session.get("username"))
    )


@insta485.app.route("/accounts/login/", methods=["POST", "GET"])
def show_login():
    """Login page."""
    if "username" in session:
        return redirect("/")
    return render_template("login.html")


@insta485.app.route("/accounts/create/")
def show_create():
    """Create account page."""
    if session.get("username"):
        return redirect("/accounts/edit/")
    return render_template("create.html")


@insta485.app.route("/accounts/logout/", methods=["POST", "GET"])
def show_logout():
    """Logout."""
    session.pop("username")
    return redirect("/accounts/login/")


@insta485.app.route("/accounts/delete/", methods=["POST", "GET"])
def show_delete():
    """Delete accounts page."""
    logname = session.get("username")
    context = {"logname": logname}
    return render_template("delete.html", **context)


@insta485.app.route("/accounts/edit/", methods=["POST", "GET"])
def show_edit():
    """Edit accounts page."""
    logname = session.get("username")
    connection = insta485.model.get_db()
    user = connection.execute(
        "SELECT * FROM users WHERE username = ?", (logname,)
    ).fetchone()
    context = {"logname": logname, "user": user}
    return render_template("edit.html", **context)


@insta485.app.route('/accounts/password/')
def show_password():
    """Password page."""
    if not flask.session.get("username"):
        return flask.redirect("/accounts/login/")
    context = {"logname": flask.session.get("username")}
    return flask.render_template("password.html", **context)


@insta485.app.route("/users/<user_url_slug>/")
def show_user(user_url_slug):
    """Display a user's profile page."""
    if "username" not in flask.session:
        return flask.redirect("/accounts/login/")

    db_connection = insta485.model.get_db()
    logname = session.get("username")

    fullname = db_connection.execute(
        "SELECT username, fullname FROM users WHERE username = ?",
        (user_url_slug,)
    ).fetchone()["fullname"]

    posts = db_connection.execute(
        "SELECT postid, filename FROM posts WHERE owner = ?",
        (user_url_slug,)
    ).fetchall()

    num_posts = len(posts)

    following_users = db_connection.execute(
        "SELECT username2 FROM following WHERE username1 = ?",
        (user_url_slug,)
    ).fetchall()

    num_following = len(following_users)

    followers = db_connection.execute(
        "SELECT username1 FROM following WHERE username2 = ?",
        (user_url_slug,)
    ).fetchall()

    num_followers = len(followers)

    is_following = any(logname in follower for follower in followers)

    context = {
        "logname": logname,
        "username": user_url_slug,
        "fullname": fullname,
        "posts": posts,
        "num_posts": num_posts,
        "num_following": num_following,
        "num_followers": num_followers,
        "is_following": is_following,
    }

    return render_template("user.html", **context)


@insta485.app.route("/users/<user_url_slug>/following/")
def show_following(user_url_slug):
    """Display the 'Following' page."""
    if "username" not in flask.session:
        return flask.redirect("/accounts/login/")

    logname = session.get("username")
    db_connection = insta485.model.get_db()

    user_following = db_connection.execute(
        "SELECT username2 AS username FROM following WHERE username1 = ?",
        (user_url_slug,)
    ).fetchall()

    log_following = db_connection.execute(
            "SELECT username2 AS username FROM following WHERE username1 = ?",
            (logname,)
        ).fetchall()

    for followed in user_following:
        followed["is_following"] = any(
            followed["username"] in log_followed["username"]
            for log_followed in log_following)

        profile = db_connection.execute(
            "SELECT filename FROM users WHERE username = ?",
            (followed["username"],)
        ).fetchone()

        followed["profile"] = profile["filename"]

    context = {"logname": logname, "following": user_following}
    context["current_page_url"] = flask.request.path
    return render_template("following.html", **context)


@insta485.app.route("/users/<user_url_slug>/followers/",
                    methods=["POST", "GET"])
def show_followers(user_url_slug):
    """Display the 'Followers' page."""
    if "username" not in flask.session:
        return flask.redirect("/accounts/login/")

    logname = session.get("username")
    db_connection = insta485.model.get_db()

    followers = db_connection.execute(
        "SELECT username1 AS username FROM following WHERE username2 = ?",
        (user_url_slug,)
    ).fetchall()

    log_following = db_connection.execute(
            "SELECT username2 AS username FROM following WHERE username1 = ?",
            (logname,)
        ).fetchall()

    for follower in followers:
        follower["is_following"] = any(
            follower["username"] in log_followed["username"]
            for log_followed in log_following)

        profile_filename = db_connection.execute(
            "SELECT filename FROM users WHERE username = ?",
            (follower["username"],)
        ).fetchone()

        follower["profile"] = profile_filename['filename']

    context = {"logname": logname, "followers": followers}
    context["current_page_url"] = flask.request.path

    return render_template("followers.html", **context)


@insta485.app.route("/posts/<postid_url_slug>/", methods=["POST", "GET"])
def show_posts(postid_url_slug):
    """Display post details page."""
    if "username" not in flask.session:
        return flask.redirect("/accounts/login/")

    logname = session["username"]

    # Connect to database
    connection = insta485.model.get_db()

    # Query the post
    post_query = connection.execute(
        "SELECT * FROM posts WHERE postid = ?",
        (postid_url_slug,)
    )
    post = post_query.fetchone()

    # Query the owner profile
    profile_query = connection.execute(
        "SELECT filename FROM users WHERE username = ?",
        (post["owner"],)
    )
    post["profile"] = profile_query.fetchone()['filename']

    # Retrieve post metadata
    post["num_likes"] = get_num_likes(post["postid"])
    post["liked"] = get_if_liked(logname, post["postid"])
    comments = get_comments(post["postid"])

    context = {"logname": logname, "post": post, "comments": comments}
    return render_template("post.html", **context)


@insta485.app.route("/explore/", methods=["GET"])
def show_explore():
    """Display explore page."""
    if "username" not in flask.session:
        return flask.redirect("/accounts/login/")

    logname = session["username"]

    # Connect to database
    connection = insta485.model.get_db()

    # Query users to follow
    cur = connection.execute(
        "SELECT username2 AS username FROM following WHERE username1 = ?",
        (logname,)
    )
    following = cur.fetchall()

    followed_users = []
    followed_users.append(logname)
    for followed in following:
        followed_users.append(followed["username"])

    query = f"SELECT * FROM users WHERE username NOT IN " \
            f"({', '.join(['?'] * len(followed_users))})"
    cur = connection.execute(query, followed_users)
    to_follows = cur.fetchall()

    context = {"logname": logname, "to_follows": to_follows}
    return render_template("explore.html", **context)


@insta485.app.route("/accounts/auth/", methods=["GET"])
def auth():
    """Check authentication."""
    if "username" in session:
        return '200'
    return abort(403)


@insta485.app.route("/likes/", methods=['POST'])
def show_likes():
    """Likes intermediate page."""
    logname = session["username"]
    connection = insta485.model.get_db()
    operation = flask.request.form.get("operation")
    postid = flask.request.form.get("postid")
    target = flask.request.args.get("target", "/")

    if operation == "like":
        if get_if_liked(logname, postid):
            abort(409)

        connection.execute(
            """
                INSERT INTO likes
                (owner, postid, created)
                VALUES (?, ?, ?)
            """,
            (logname, postid, arrow.now().format('YYYY-MM-DD HH:mm:ss'), )
        )
    elif operation == "unlike":
        if not get_if_liked(logname, postid):
            abort(409)

        connection.execute(
            "DELETE FROM likes WHERE owner = ? AND postid = ?",
            (logname, postid)
        )
    return redirect(target)


@insta485.app.route("/comments/", methods=['POST'])
def process_comments():
    """Comments intermediate page."""
    logname = session["username"]
    connection = insta485.model.get_db()
    if "operation" not in flask.request.form:
        flask.abort(400)
    operation = flask.request.form.get("operation")
    target = flask.request.args.get("target", "/")

    if operation == "create":
        if "text" not in flask.request.form:
            flask.abort(400)
        text = flask.request.form.get("text")
        if len(text) == 0:
            abort(403)

        if "postid" not in flask.request.form:
            flask.abort(400)
        postid = flask.request.form.get("postid")
        if len(postid) == 0:
            abort(403)

        connection.execute(
            """
                INSERT INTO comments
                (owner, postid, text, created)
                VALUES (?, ?, ?, ?)
            """,
            (logname, postid, text,
             arrow.now().format('YYYY-MM-DD HH:mm:ss'), )
        )
    elif operation == "delete":
        if "commentid" not in flask.request.form:
            flask.abort(400)

        commentid = flask.request.form.get("commentid")
        if len(commentid) == 0:
            abort(403)

        cur = connection.execute(
            "SELECT owner FROM comments WHERE commentid = ?",
            (commentid, )
        )
        owner = cur.fetchone()["owner"]

        if owner != logname:
            abort(403)
        else:
            connection.execute(
                "DELETE FROM comments WHERE commentid = ?", (commentid, )
            )
    else:
        flask.abort(400)
    return redirect(target)


@insta485.app.route("/posts/", methods=['POST'])
def process_posts():
    """Comments intermediate page."""
    logname = session["username"]
    connection = insta485.model.get_db()
    operation = flask.request.form.get("operation")
    postid = flask.request.form.get("postid")
    target = flask.request.args.get("target")
    # print("start")
    # print('target:', target)
    if operation == "create":
        uploaded_file = flask.request.files.get("file")

        if len(uploaded_file.filename) == 0:
            abort(403)

        filename = uploaded_file.filename
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix.lower()
        uuid_basename = f"{stem}{suffix}"

        path = insta485.app.config["UPLOAD_FOLDER"] / uuid_basename
        uploaded_file.save(path)

        connection.execute(
            """
                INSERT INTO posts
                (filename, owner, created)
                VALUES (?, ?, ?)
            """,
            (uuid_basename, logname,
             arrow.now().format('YYYY-MM-DD HH:mm:ss'), )
        )
    elif operation == "delete":
        cur = connection.execute(
            "SELECT owner FROM posts WHERE postid = ?",
            (postid, )
        )
        owner = cur.fetchone()["owner"]

        cur = connection.execute(
            "SELECT filename FROM posts WHERE postid = ?",
            (postid, )
        )
        filename = cur.fetchone()['filename']

        if owner != logname:
            abort(403)
        if len(filename) == 0:
            flask.abort(409)
        path = insta485.app.config["UPLOAD_FOLDER"]/filename
        os.remove(path)

        connection.execute(
            "DELETE FROM posts WHERE postid = ?", (postid)
        )

    if target is None:
        return redirect(
            flask.url_for("show_user", user_url_slug=flask.session["username"])
        )

    return redirect(target)


@insta485.app.route("/following/", methods=['POST'])
def process_following():
    """Comments intermediate page."""
    logname = session["username"]
    connection = insta485.model.get_db()
    operation = flask.request.form.get("operation")
    username = flask.request.form.get("username")
    target = flask.request.args.get("target", "/")

    if operation == "follow":
        cur = connection.execute(
            "SELECT username1 FROM following WHERE username2 = ?",
            (username, )
        )
        followers = cur.fetchall()

        if logname in followers:
            abort(403)

        connection.execute(
            """
                INSERT INTO following
                (username1, username2, created)
                VALUES (?, ?, ?)
            """,
            (logname, username, arrow.now().format('YYYY-MM-DD HH:mm:ss'), )
        )
    elif operation == "unfollow":
        cur = connection.execute(
            "SELECT username2 AS username FROM following WHERE username1 = ?",
            (logname, )
        )
        following = cur.fetchall()

        if not any(username in follows["username"] for follows in following):
            abort(403)

        connection.execute(
            "DELETE FROM following WHERE username1 = ? AND username2 = ?",
            (logname, username)
        )
    return redirect(target)


@insta485.app.route("/uploads/<path:name>")
def download_file(name):
    """Check if user is loggedin and send requested file."""
    if "username" not in flask.session:
        flask.abort(403)
    folder = insta485.config.UPLOAD_FOLDER
    return flask.send_from_directory(folder, name, as_attachment=True)


def encrypt_password(salt, password):
    """Encrypt password using the given salt."""
    algorithm = 'sha512'
    hash_obj = hashlib.new(algorithm)
    salted_password = salt + password
    hash_obj.update(salted_password.encode('utf-8'))
    hashed_password = hash_obj.hexdigest()
    return "$".join([algorithm, salt, hashed_password])


def if_valid_password(username, password):
    """Check if the password is valid."""
    # Get original password
    connection = insta485.model.get_db()
    cursor = connection.execute(
        "SELECT password FROM users WHERE username = ?", (username,)
    )
    password_from_db = cursor.fetchone()
    if password_from_db is None:
        return False

    password_from_db = password_from_db["password"]
    _, salt, _ = password_from_db.split("$")

    # Hash password
    hashed_password_from_db = encrypt_password(salt, password)
    return hashed_password_from_db == password_from_db


def get_num_likes(post_id):
    """Get the number of likes for a post."""
    connection = insta485.model.get_db()
    cursor = connection.execute(
        "SELECT COUNT(*) AS count FROM likes WHERE postid = ?", (post_id,)
    )
    return cursor.fetchone()["count"]


def get_if_liked(username, post_id):
    """Check if a user liked a post."""
    connection = insta485.model.get_db()
    cursor = connection.execute(
        """
        SELECT COUNT(*) AS count FROM likes
        WHERE postid = ? AND owner = ?
        """,
        (post_id, username)
    )
    return cursor.fetchone()["count"] > 0


def get_comments(post_id):
    """Get comments for a post."""
    connection = insta485.model.get_db()
    cursor = connection.execute(
        """
        SELECT * FROM comments
        WHERE postid = ?
        ORDER BY created DESC
        """,
        (post_id,)
    )
    return cursor.fetchall()
