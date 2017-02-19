import webapp2
import os
import re
import jinja2
import random
import hashlib
import hmac
import time
from google.appengine.ext import db
from string import letters

template_directory = os.path.join(os.getcwd(), 'templates')
#template_directory = os.path.join(os.path.dirname(__file__), 'templates')
jinja_environment = jinja2.Environment(loader = jinja2.FileSystemLoader(template_directory), autoescape = True)

# The Handler class is a basic request handler webapp2 style.
class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_environment.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# Handles loading the main page with all the created blogs.
class MainPageHandler(Handler):

    def get(self):

        # default login button and message not logged in.
        login = "LOGIN"
        message = "You are not logged in."
        user_cookie = self.request.cookies.get('name_id')

        # check if someone is logged in to change status of login button.
        user_id = UserManager().get_user_id(user_cookie)
        if user_id:
            login = "LOGOUT"
            message = "You are logged in as: " + User.get_by_id(long(user_id)).username

        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC LIMIT 10")
        likes = VoteManager().get_total_likes()
        dislikes = VoteManager().get_total_dislikes()
        time.sleep(0.4)
        # determine if there are blogs.
        noblogs = self.blogs_empty(blogs)
        self.render("index.html", blogs=blogs, noblogs=noblogs, likes=likes, dislikes=dislikes, login=login, message=message)

    # handle votes.
    def post(self):
        # default login button and message not logged in.
        login = "LOGIN"
        message = "You are not logged in."
        # list blogs
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC LIMIT 10")
        likes = VoteManager().get_total_likes()
        dislikes = VoteManager().get_total_dislikes()
        time.sleep(0.4)
        # again the default login button and message.
        user_cookie = self.request.cookies.get('name_id')
        # need the id of the blog to place vote or comment on.
        blog_id = self.request.get('current_blog')
        # check if someone is logged in to change status of login button.
        user_id = UserManager().get_user_id(user_cookie)
        if user_id:
            login = "LOGOUT"
            message = "You are logged in as: " + User.get_by_id(long(user_id)).username
            # check if this is not the user of the blog.
            blog_user = db.GqlQuery("SELECT user FROM Vote WHERE blog =:1", blog_id)
            if blog_user == user_id:
                voting_error = "You cannot like or dislike your own Blogs."
                self.render('index.html', login=login, voting_error = voting_error, blogs=blogs, likes=likes, dislikes=dislikes)
                return
        if not user_id:
            login_error = "To like or dislike you must login."
            self.render("index.html", login=login, login_error = login_error, blogs=blogs, likes=likes, dislikes=dislikes)
            return
        # create a vote (determine if it is a like or dislike)
        like = False
        if self.request.get('like') == "True":
            like = True
        # check if there was a vote else if there was not send a message.
        if VoteManager().place_vote(user_id, blog_id, like):
            # vote was placed
            self.redirect('/')
            return
        # vote not placed error
        voting_error = "Something went wrong while placing a vote."
        self.render("index.html", login=login, voting_error=voting_error, blogs=blogs, likes=likes, dislikes=dislikes)

    def blogs_empty(self, blogs):

        for blog in blogs:
            if blog:
                return False
        return True


# Bring the user to a welcome page with information.
class SigninHandler(Handler):

    def get(self):
        # to give the username back in case of "bouncing back the login form".
        params = {}
        self.render("signin.html", params=params)

    # handle the signin procedure of the form.
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        # error flag, set False as default (which is kind of creepy).
        error = False
        # error_handling parameters.
        no_username = invalid_username = no_password = invalid_password = no_verify = invalid_verify = invalid_email = ""
        params = {'username': username, 'password': password, 'verify':  verify, 'email': email,
        'no_username': no_username, 'invalid_username': invalid_username, 'no_password': no_password,
        'invalid_password': invalid_password, 'no_verify': no_verify, 'invalid_verify': invalid_verify,
        'invalid_email': invalid_email}

        # check if the form fields are filled in and/or correct.
        # form error messages accordingly.
        # username (filled in, legal).
        if not username:
            params['no_username'] = "Username is required."
            error = True
        elif not CheckingValues().valid_username(username):
            params['invalid_username'] = "This is not a valid username."
            error = True
        # password filled in? legal?
        if not password:
            params['no_password'] = "Password is a required field."
            error = True
        elif not CheckingValues().valid_password(password):
            params['invalid_password'] = "This is not a valid password."
            error = True
        # verify filled in? and same as password?
        if not verify:
            params['no_verify'] = "You need to verify the password."
            error = True
        elif not CheckingValues().match_pass(password, verify):
            params['invalid_verify'] = "Password and verify do not match."
            error = True
        if email and not CheckingValues().valid_email(email):
            params['invalid_email'] = "This is not a valid email address."
            error = True
        # render the form back if error
        if error == True:
            self.render("signin.html", params = params)
            return
        else:
            # create the User in database but if this username already exists
            # the form must re-render and an error message must be displayed.
            if not UserManager().createUser(username, password, email):
                existing_user = "Sorry this username is already taken!"
                params['existing_user'] = existing_user
                self.render("signin.html", params=params)
                return
        # 2. autologin user (dangerous!)
        time.sleep(0.4)
        header = UserManager().login(username, password)
        self.response.headers.add_header(header[0], header[1])
        self.redirect("/welcome?username="+username)

# Utility class for checking validity of values from forms.
class CheckingValues():

    # check username.
    def valid_username(self,username):
        USERNAME = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USERNAME.match(username)
    # check for valid password.
    def valid_password(self,password):
        USERPASS = re.compile(r"^.{3,20}$")
        return USERPASS.match(password)
    # check for matching password-verification.
    def match_pass(self, password , verify ):
        if password == verify:
            return True
        else:
            return False
    # check for valid email address.
    def valid_email(self, email):
        USERMAIL = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return USERMAIL.match(email)


# Model Blog contains a subject, content, created (date) and last_modified (date last modified).
class Blog(db.Model):

    user_id = db.StringProperty(required = True)
    title = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

class BlogManager():
    # Create a blog and put it in the database.
    def createBlog(self, user_id, title, content):
        blog = Blog(parent = self.blog_key(), user_id = user_id, title = title, content = content)
        blog_key = blog.put() # the key of the blog
        return blog_key

    # managing blog Keys.
    def blog_key(self, blog_id = 'default'):
        return db.Key.from_path('blogpage', blog_id)

# Handles creation of blogs consisting of a subject and content.
# PRETTY WELL DONE, FOR THE RECORD
class BlogHandler(Handler):

    def get(self):
        title = self.request.get('title')
        content = self.request.get('content')
        params = {'title':title,'content':content}
        self.render("create_blog.html", params=params)

    def post(self):
        # The user is the current user
        user_cookie = self.request.cookies.get('name_id')
        # is logged in so get the user_id
        user_id = UserManager().get_user_id(user_cookie)
        if not user_id:
            self.render("login.html")
        # get the two inputs from input fields
        title = self.request.get('title')
        content = self.request.get('content')
        # three different variables for three separate messages.
        all_empty = missing_title = missing_content = ""
        params = {'title': title, 'content' : content, 'all_empty': all_empty, 'missing_title': missing_title
        ,'missing_content':missing_content}
        # now check of the title and content are set.
        if title and content:
            # title and content are set so do the post
            b_key = BlogManager().createBlog(user_id, title, content)
            self.redirect("/blogpage/%d" % b_key.id())
            # self.redirect('/')
        # one of two or both are not set so construct error accordingly and render page anew.
        elif not title and not content:
            params['all_empty'] = "Both fields are empty you need to fill in the title and content."
        elif not title:
            params['missing_title'] = "You forgot to fill in the title, it is required."
        elif not content:
            params['missing_content'] = "The content is missing, it is required."
        self.render("create_blog.html", params = params)
        # create a blog and put it in the database via BlogManager.
        # BlogManager().createBlog(user_id, title, content)

# Handle logging in
class LoginHandler(Handler):

    def get(self):
        self.render("login.html", login="LOGIN")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        user = User.all().filter('username =', username).get()
        if user and SecureValues().valid_password(username, password, user.password_hash):
            new_cookie_val = SecureValues().make_secure_value(str(user.key().id()))
            self.response.headers.add_header('Set-Cookie', "name_id=%s; Path=/" % new_cookie_val)
            self.redirect('/welcome?username='+username)
        else:
            self.render("login.html", username=username, error="Sorry invalid login.")

# class for checking and making security values: passwords, hashes and cookies.
class SecureValues():

    # check if this is valid password.
    def valid_password(self, name, password, hash_h):
        salt = hash_h.split('|')[0]
        return hash_h == self.make_secure_password(name, password, salt)

    # make secure value return tuple (value, some_digest_of_value).
    def make_secure_value(self, value):
        # a secret value to obfuscate the truth, it's out there...
        secret = 'ANOTHER_DAMNED_SECRET'
        return '%s|%s' % (value, hmac.new(secret, value).hexdigest())

    # authenticate the value, make sure it is ok.
    def check_secure_value(self, secure_value):
        value = secure_value.split('|')[0]
        if secure_value == self.make_secure_value(value):
            return value

    # set a secure cookie with the secure value for authenticating users.
    def set_secure_cookie(self, name, value):
        cookie_value = self.make_secure_value(value)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_value))

    # make a salt of 5 characters.
    def make_salt(self, length = 5):
        return ''.join(random.choice(letters) for x in xrange(length))

    # make a secure password, parameters name, password and salt (if None create one).
    # @return a string with salt and hash separated by a | symbol.
    def make_secure_password(self, name, password, salt = None):
        if not salt:
            salt = self.make_salt()
        hash_h = hashlib.sha256(name + password + salt).hexdigest()
        return '%s|%s' % (salt, hash_h)


# Handling logging out, delete the cookie authenticating the user.
class LogoutHandler(Handler):
    def get(self):
        # reset cookie and redirect to homepage.
        self.response.headers.add_header('Set-Cookie', "name_id=; Path=/")
        self.redirect('/')

# User class for the user database
# User has a name, password in the form of a hash and an email (optional).
class User(db.Model):
    # The table user contains a username, password, email.
    username = db.StringProperty(required = True)
    password_hash = db.StringProperty(required = True)
    email = db.StringProperty()

class UserManager():
    # function for creating users, returns False if user already exists.
    def createUser(self, username, password, email=None):
        # check if the username already exists.
        user = User.all().filter('username =', username).get()
        # if user is not None then it is an existing user.
        if user:
            return False;
        # Make a password hash with a salt and store that in database.
        password_hash = SecureValues().make_secure_password(username, password)
        user = User(username = username, password_hash = password_hash, email = email)
        user.put()
        return True

    # logout this user, by resetting the cookie and then redirecting to login page.
    # returns a tuple with header
    def logout():
        # return string to set header
        return ('Set-Cookie', "name_id=; Path=/")

    # Try to login return a cookie value if succeeded else return None.
    def login(self, username, password):

        user = User.all().filter('username =', username).get()
        if user and SecureValues().valid_password(username, password, user.password_hash):
            new_cookie_value = SecureValues().make_secure_value(str(user.key().id()))
        return ('Set-Cookie', "name_id=%s; Path=/" % new_cookie_value)

    # if the user is logged in then the id is set...else it is none
    def get_user_id(self, user_cookie):
        if not user_cookie:
            return None
        return SecureValues().check_secure_value(user_cookie)

# Comment class, with user (who create this comment), blog (on what blog), content.
class Comment(db.Model):

    user = db.StringProperty(required = True)
    blog = db.StringProperty(required = True)
    comment = db.TextProperty(required = True)

# Manages Comments (Database: Comment)
class CommentManager():

    # Creation of comments.
    def createComment(self, user, blog, comment):
        comment = Comment(user=user, blog=blog, comment=comment)
        comment.put()
    # Deletion of comments.
    def deleteComment(self, user, blog_id):
        # a user can only delete their own comment.

        # a question must be raised: are you sure you want to delete this comment?
        pass

    # returns a list of comments (per blog).
    def get_comments_per_blog(self, blog_id):
        return db.GqlQuery("SELECT * FROM Comment WHERE ID =:1",blog_id)

# Vote class, user (the voter), blog (voted on), like, dislike.
class Vote(db.Model):

    user = db.StringProperty(required = True)
    blog = db.StringProperty(required = True)
    vote_opinion = db.BooleanProperty()

# Manages Votes (Database: Vote)
class VoteManager():

    def place_vote(self, user_id, blog_id, the_vote):

        # no voting on yourself.
        blog_creator = db.GqlQuery("SELECT user_id FROM Blog WHERE ID =:1",blog_id)
        if blog_creator == user_id:
            return False # no self voting.
        # check if this blog has been voted upon already.
        like = db.GqlQuery("SELECT vote_opinion FROM Vote WHERE user =:1 AND blog =:2",user_id, blog_id)
        if like == True or like == False:
            return False # already voted.

        vote = Vote(user = user_id , blog = blog_id, vote_opinion = the_vote)
        vote.put()
        return True # newly voted

    def get_total_likes(self):
        like_votes = db.GqlQuery("SELECT * FROM Vote WHERE vote_opinion = True")
        likes = 0
        for vote in like_votes:
            likes += 1
        return likes

    def get_total_dislikes(self):
        dislike_votes = db.GqlQuery("SELECT * FROM Vote WHERE vote_opinion = False")
        dislikes = 0
        for vote in dislike_votes:
            dislikes += 1
        return dislikes

class ShowBlogHandler(Handler):

    # show blog via key.
    def get(self, blog_id):
        blog = Blog.get_by_id(int(blog_id),parent=BlogManager().blog_key())
        if not blog:
            self.error(404)
            return
        self.render("blogpage.html", blog = blog)

# WelcomePageHandler handles rendering of the welcome page.
class WelcomePageHandler(Handler):

    def get(self):
        username = self.request.get('username')
        # The user is the current user
        user_cookie = self.request.cookies.get('name_id')
        user_id = UserManager().get_user_id(user_cookie)
        if not user_id:
            self.redirect('/signin')
            return
        # get the blogs this user created.
        blogs = db.GqlQuery("SELECT * FROM Blog WHERE user_id =:1", user_id)
        # user is logged in create Logout button
        login = "LOGOUT"
        self.render('welcome.html', username = username, blogs = blogs, login=login)

# Handling comments, creating comments and editing or even removing them.
class CommentHandler(Handler):

    def get(self):
        user_cookie = self.request.cookies.get('name_id')
        blog_id = self.request.get('current_blog')
        blog = Blog.get_by_id(long(blog_id), parent=BlogManager().blog_key())
        # need to be logged in to comment!
        if not UserManager().get_user_id(user_cookie):
            self.redirect('/signin')
        self.render('comment.html', blog = blog)

    def post(self):
        # to give comments you must be logged in.
        user_cookie = self.request.cookies.get('name_id')
        if not UserManager().get_user_id(user_cookie):
            login_error = "Sorry you need to be logged in to place comments!"
            self.render('index.html', login_error)
            return
        # create the comments in database
        comment = self.request.get('comment')
        if comment:
            CommentManager().create(user_id, blog_id, comment)
        self.render('index.html')

# Handling votes: both likes and dislikes.
class VoteHandler(Handler):

    def post(self):
        # to vote you must be logged in.
        user_cookie = self.request.cookies.get('name_id')
        blog_id = self.request.get('current_blog')
        user_id = UserManager().get_user_id(user_cookie)
        if not user_id:
            # not logged in, display error message.
            login_error = "To place votes you must login."
            self.redirect('/?login=False')
            return
        # create a vote (determine if it is a like or dislike)
        like = False
        if self.request.get('like') == "True":
            like = True
        # check if there was a vote else if there was not send a message.
        if VoteManager().place_vote(user_id, blog_id, like):
            self.redirect('/')

# Handling Editing the blog, and possible removing the blog.
class EditBlogHandler(Handler):
    def get(self):
        pass
    def post(self):
        pass

# this is the routing that is used in the application
# consists of path to HandlerName pairs watch out Debug = True must be set to
# False if you want to deploy safely.
app = webapp2.WSGIApplication([('/', MainPageHandler),
                               ('/create_blog', BlogHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/signin', SigninHandler),
                               ('/welcome', WelcomePageHandler),
                               ('/comment', CommentHandler),
                               ('/vote', VoteHandler),
                               ('/edit', EditBlogHandler),
                               ('/blogpage/([0-9]+)', ShowBlogHandler)
                               ], debug = True)
