from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from dbSetup import Base, Sport, CatologueItem, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

# Connect to Database and create database session
engine = create_engine('sqlite:///sportCatologue.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase+string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
# Validate state token
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: '
    output += '150px;-webkit-border-radius: '
    output += '150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
                                'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?'
    url += 'grant_type=fb_exchange_token&client_id=%s&'
    url += 'client_secret=%s&'
    url += 'fb_exchange_token'
    url += '=%s' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token'
    url += '=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token'
    url += '=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: '
    output += '300px;border-radius: 150px;-webkit-border-radius: '
    output += '150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/'
    url += 'permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            # del login_session['gplus_id']
            # del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showSports'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showSports'))


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# JSON APIs to view Sport Information
@app.route('/sports/<int:sport_id>/catologue/JSON')
def sportJSON(sport_id):
    sport = session.query(
                         Sport).filter_by(id=sport_id).one()
    catologueItems = session.query(
                                  CatologueItem).filter_by(
                                  sport_id=sport_id).all()
    return jsonify(CatologueItems=[i.serialize for i in catologueItems])


@app.route('/sports/<int:sport_id>/catologue/<int:catologue_id>/JSON')
def catologueItemJSON(sport_id, catologue_id):
    catologueItem = session.query(
                                 CatologueItem).filter_by(
                                 id=catologue_id).one()
    return jsonify(Catologue_Item=catologueItem.serialize)


@app.route('/sports/JSON')
def sportsJSON():
    sports = session.query(Sport).all()
    return jsonify(sports=[s.serialize for s in sports])


# homepage to show all the sports
@app.route("/")
@app.route("/sports/")
def showSports():
    sports = session.query(Sport).order_by(asc(Sport.name))
    if 'username' not in login_session:
        return render_template('publichomepage.html', sports=sports)
    return render_template('homepage.html', sports=sports)


# create a new sport
@app.route('/sports/new', methods=['GET', 'POST'])
def newSport():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newSport = Sport(name=request.form['name'])
        session.add(newSport)
        flash('New Sport %s added!' % newSport.name)
        session.commit()
        return redirect(url_for('showSports'))
    else:
        return render_template('newSport.html')


# Edit a sport
@app.route('/sports/<int:sport_id>/edit/', methods=['GET', 'POST'])
def editSport(sport_id):
    editedSport = session.query(Sport).filter_by(id=sport_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedSport.user_id != login_session['user_id']:
        add = "<script>function myFunction() {alert("
        add += "'You are not authorized to edit this sport. "
        add += "Please create your own sport in order to edit.')"
        add += ";}</script><body onload='myFunction()'>"
        return add
    if request.method == 'POST':
        if request.form['name']:
            editedSport.name = request.form['name']
            flash('Sport edited %s!' % editedSport.name)
            return redirect(url_for('showSports'))
    else:
        return render_template('editSport.html', sport=editedSport)


# Delete a sport
@app.route('/sports/<int:sport_id>/delete/', methods=['GET', 'POST'])
def deleteSport(sport_id):
    sportToDelete = session.query(Sport).filter_by(id=sport_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if sportToDelete.user_id != login_session['user_id']:
        add = "<script>function myFunction() {alert('You "
        add += "are not authorized to delete this sport. Please create "
        add += "your own sport in order to delete.');}"
        add += "</script><body onload='myFunction()'>"
        return add
    if request.method == 'POST':
        session.delete(sportToDelete)
        flash('%s deleted!' % sportToDelete.name)
        session.commit()
        return redirect(url_for('showSports'))
    else:
        return render_template('deleteSport.html', sport=sportToDelete)


# show a catologue in the sport
@app.route("/sports/<int:sport_id>/")
@app.route("/sports/<int:sport_id>/catologue/")
def showCatologue(sport_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    items = session.query(CatologueItem).filter_by(sport_id=sport_id).all()
    creator = getUserInfo(sport.user_id)
    if ('username' not in login_session or
            creator.id != login_session['user_id']):
        return render_template('publicCatologueMenu.html',
                               catologueItems=items,
                               sport=sport, creator=creator)
    else:
        return render_template('catologueMenu.html',
                               catologueItems=items,
                               sport=sport, creator=creator)


# Edit a CatologueItem
@app.route(
           "/sports/<int:sport_id>/catologue/<int:catologue_id>/edit/",
           methods=['GET', 'POST'])
def editCatologueItem(sport_id, catologue_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(CatologueItem).filter_by(id=catologue_id).one()
    sport = session.query(Sport).filter_by(id=sport_id).one()
    if login_session['user_id'] != sport.user_id:
        add = "<script>function myFunction() {alert('You are not authorized "
        add += "to edit menu items to this restaurant. Please create your own "
        add += "restaurant in order to edit items.');}"
        add += "</script><body onload='myFunction()'>"
        return add

    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash('catologue Item added!')
        return redirect(url_for('showCatologue', sport_id=sport_id))
    else:
        return render_template('editCatologueItem.html',
                               sport_id=sport_id,
                               catologue_id=catologue_id, item=editedItem)


# Create a new catologue item
@app.route('/sports/<int:sport_id>/catologue/new/', methods=['GET', 'POST'])
def newCatologueItem(sport_id):
    if 'username' not in login_session:
        return redirect('/login')
    sport = session.query(Sport).filter_by(id=sport_id).one()
    if login_session['user_id'] != sport.user_id:
        add = "<script>function myFunction() {alert('You are not "
        add += "authorized to add menu items to this restaurant. "
        add += "Please create "
        add += " your own restaurant in order to add items.');}"
        add += "</script><body onload='myFunction()'>"
        return add
    if request.method == 'POST':
        newCatologueItem = CatologueItem(
                        name=request.form['name'],
                        description=request.form['description'],
                        sport_id=sport_id,
                        user_id=sport.user_id)
        session.add(newCatologueItem)
        session.commit()
        flash('New catologue item %s added!' % (newCatologueItem.name))
        return redirect(url_for('showCatologue', sport_id=sport_id))
    else:
        return render_template('newCatologueItem.html',
                               sport_id=sport_id,
                               sport=sport)


# Delete a catologue item
@app.route(
           '/sports/<int:sport_id>/catologue/<int:catologue_id>/delete/',
           methods=['GET', 'POST'])
def deleteCatologueItem(sport_id, catologue_id):
    if 'username' not in login_session:
        return redirect('/login')
    sport = session.query(Sport).filter_by(id=sport_id).one()
    itemToDelete = session.query(
                                 CatologueItem).filter_by(
                                 id=catologue_id).one()
    if login_session['user_id'] != sport.user_id:
        add = "<script>function myFunction() {alert('You are not authorized "
        add += "to delete menu items to this restaurant."
        add += "Please create your own restaurant in order to delete "
        add += "items.');}</script><body onload='myFunction()'>"
        return add
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Catologue Item Successfully Deleted')
        return redirect(url_for('showCatologue', sport_id=sport_id))
    else:
        return render_template('deleteCatologueItem.html',
                               item=itemToDelete, sport_id=sport_id)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
