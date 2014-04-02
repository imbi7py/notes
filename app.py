from functools import wraps
from flask import (
    Flask,
    request,
    url_for,
    redirect,
    render_template,
    session,
    flash,
    g
)
from flask_oauthlib.client import OAuth
from flask.ext.pymongo import PyMongo
app = Flask(__name__)
app.debug = True
app.secret_key = 'development'

mongo = PyMongo(app)
oauth = OAuth(app)
twitter = oauth.remote_app(
    'twitter',
    consumer_key='consumerkey',
    consumer_secret='secretkey',
    base_url='https://api.twitter.com/1.1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authenticate'
)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@twitter.tokengetter
def get_twitter_token():
    return session.get('auth')


@app.before_request
def before_request():
    g.user = session.get('auth')


@app.route('/login')
def login():
    callback_url = url_for(
        'oauthorized',
        next=request.args.get('next') or request.referrer or None
    )
    return twitter.authorize(callback=callback_url)


@app.route('/logout')
def logout():
    session.pop('auth', None)
    return redirect(url_for('index'))


@app.route('/oauthorized')
@twitter.authorized_handler
def oauthorized(resp):
    next_url = request.args.get('next') or url_for('index')
    if resp is None:
        flash(u'There was a problem authenticating')
        return redirect(next_url)

    session['auth'] = resp
    # find and upsert user
    mongo.db.users.find_and_modify(
        {'twitter.user_id': resp['user_id']},
        {'$set': {'twitter': resp}},
        True)
    return redirect(url_for('index'))


@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run()
