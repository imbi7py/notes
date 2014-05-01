from functools import wraps
from datetime import datetime

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

from flask_wtf import Form
from wtforms import TextField, TextAreaField, Field
from wtforms.validators import DataRequired
from wtforms.widgets import TextInput
from flask_oauthlib.client import OAuth
from flask.ext.pymongo import PyMongo

from bson import ObjectId

app = Flask(__name__)
app.debug = True
app.secret_key = 'development'

mongo = PyMongo(app)
oauth = OAuth(app)
twitter = oauth.remote_app(
    'twitter',
    consumer_key='gdNUVunzxby30FpeMkgeBoV0y',
    consumer_secret='Py5pVd8iV1huetT8pGOlXZZ2t0aGvZaFBeDtmVjgxSac17wVLx',
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
    g.user = None
    if 'auth' in session and '_id' in session['auth']:
        g.user = mongo.db.users.find_one(
            {'_id': ObjectId(session['auth']['_id'])}
        )


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
        flash('There was a problem authenticating')
        return redirect(next_url)

    # find and upsert user
    user = mongo.db.users.find_and_modify(
        {'twitter.user_id': resp['user_id']},
        {'$set': {'twitter': resp}},
        True, new=True)
    user['_id'] = str(user['_id'])
    session['auth'] = user
    return redirect(url_for('index'))


@app.route('/')
def index():
    notes = None
    if g.user:
        notes = mongo.db.notes.find({'user': g.user['_id']})
    return render_template('index.html', notes=notes)


@app.route('/note/<ObjectId:note>', methods=('GET', 'POST'))
@login_required
def note_edit(note):
    form = NoteForm()
    if form.validate_on_submit():
        # we can assume that this is secure since we're searching on both
        # constraints for the note
        note = mongo.db.notes.find_one_or_404(
            {'_id': note, 'user': g.user['_id']})
        note.update({
            'title': form.title.data,
            'body': form.body.data,
            'tags': form.tags.data,
            'ts': datetime.now()
        })
        mongo.db.notes.save(note)
        return redirect(url_for('index'))

    note = mongo.db.notes.find_one_or_404({'_id': note, 'user': g.user['_id']})
    form = NoteForm(**note)
    return render_template('note_edit.html', form=form, action=request.path)


@app.route('/note/', methods=('GET', 'POST'))
@login_required
def new_note():
    form = NoteForm()
    if form.validate_on_submit():
        # the order of this is important for security
        data = {
            'user': g.user['_id'],
            'title': form.title.data,
            'body': form.body.data,
            'tags': form.tags.data,
            'ts': datetime.now()
        }
        mongo.db.notes.insert(data)
        return redirect(url_for('index'))
    return render_template('note_edit.html', form=form, action=request.path)


class TagListField(Field):
    widget = TextInput()

    def __init__(
            self, label='', validators=None, remove_duplicates=True, **kwargs):
        super(TagListField, self).__init__(label, validators, **kwargs)
        self.remove_duplicates = remove_duplicates

    def _value(self):
        if self.data:
            return u', '.join(self.data)
        else:
            return u''

    def process_formdata(self, valuelist):
        # could do all of this in one pass but cleaner to read this way
        # and takes trivial amount of time
        if valuelist:
            self.data = [x.strip() for x in valuelist[0].split(',')]
        else:
            self.data = []

        if self.remove_duplicates:
            self.data = list(self._remove_duplicates(self.data))

    @classmethod
    def _remove_duplicates(cls, seq):
        """Remove dupes in a case insensitive, but case preserving manner"""
        d = {}
        for item in seq:
            if item.lower() not in d:
                d[item.lower()] = True
                yield item


class NoteForm(Form):
    title = TextField('name', validators=[DataRequired()])
    body = TextAreaField('body', validators=[DataRequired()])
    tags = TagListField('tags')

if __name__ == '__main__':
    mongo.db.ensureIndex()
    app.run()
