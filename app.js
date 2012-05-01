var fs = require('fs')
  , crypto = require('crypto')
  , express = require('express')
  , punch = require('punch')
  , everyauth = require('everyauth')
  , jade = require('jade')
  , passhash = require('password-hash')
  , app = require('express').createServer();

var alphanum = new RegExp('^[A-Za-z0-9]+$');

everyauth.debug = true;

var nano = require('nano')('http://localhost:5984');
var db = nano.use('pressiv');
var dbobj;
db.get('pressiv_users', {}, function (err, body) {
    if (!err) {
	dbobj = body;
    }
});

function checkForLogin(login) {
    for (login in dbobj.users)
	if (dbobj.users[login].login == login)
	    return true;
    return false;
}

function getUserByLogin(login) {
    for (user in dbobj.users)
	if (login == dbobj.users[user].login)
	    return dbobj.users[user];
    return false;
}

function makeDirectories(newname) {
    var folders = ['/contents/', '/templates/', '/public/'];
    for (folder in folders)
	fs.mkdir(__dirname + folders[folder] + newname);
}

function insertCallback(err, body) {
    if (!err)
	console.log(body);
    else
	console.log(err);
}

everyauth.everymodule.findUserById( function (id, callback) {
    callback(null, dbobj.users[id]);
});

everyauth.password
    .getLoginPath('/log_in')
    .postLoginPath('/log_in')
    .loginView('login.jade')
    .authenticate( function (login, password) {
	var errors = [];
	if (!login) errors.push('Missing login');
	if (!password) errors.push('Missing password');
	if (errors.length) return errors;
	var user = getUserByLogin(login);
	if (!user) return ['Login failed'];
	if (!passhash.verify(password, user.password)) return ['Login failed'];
	return user;
    })
    .loginSuccessRedirect('/')
    .getRegisterPath('/sign_up')
    .postRegisterPath('/sign_up')
    .registerView('register.jade')
    .validateRegistration( function (newUserAttrs) {
	var errors = [];
	var login = newUserAttrs.login;
	if (!login.match(alphanum)) errors.push('Login must be alphanumeric');
	if (login.length < 5) errors.push('Login must be at least 5 characters long');
	if (checkForLogin(login)) errors.push('Login already taken');
	return errors;
    })
    .registerUser( function (newUserAttrs) {
	var login = newUserAttrs.login;
	makeDirectories(login);
	var pass = newUserAttrs.password;
	dbobj.last_id++;
	var id = dbobj.last_id;
	dbobj.users[id] = new Object;
	dbobj.users[id].login = login;
	dbobj.users[id].id = id;
	dbobj.users[id].password = passhash.generate(pass);
	dbobj.users[id].presentations = new Object;
	db.insert(dbobj, 'pressiv_users', insertCallback);
	return dbobj.users[id];
    })
    .registerSuccessRedirect('/');

app.use(express.bodyParser());
app.use(express.cookieParser());
app.use(express.session({'secret': 'htuayreve'}));
app.use(everyauth.middleware());
app.use(app.router);
everyauth.helpExpress(app);
app.set('view engine', 'jade');

app.get('/', function(req, res, next) {
    //fs.readFile('index.html', function(err, data) {
    //if (err) throw err;
    //res.send(data, {'Content-type': 'text/html'});
    //});
    res.render('index.jade');
});

app.post('/new', function(req, res, next) {
    var name = req.body.name;
    if (req.user) {
	if (!name.match(alphanum)) {
	    res.render('new.jade', {'errors': ['Presentation name must be alphanumeric']});
	    return;
	}
	var presentations = dbobj.users[req.user.id].presentations;
	var notexist = true;
	if (typeof(presentations[name]) != "undefined")
	    notexist = false;
	if (notexist) {
	    newpres = new Object;
	    newpres.name = name;
	    newpres.slides = new Array;
	    presentations[name] = newpres;
	    makeDirectories(req.user.login + name);
	    db.insert(dbobj, 'pressiv_users', insertCallback);
	    res.redirect('/edit?presentation=' + name);
	}
    } else {
	res.redirect('/');
    }
});

app.get('/*', function(req, res, next) {
    var resource = req.params[0];
    if (resource.lastIndexOf('/') + 1 == resource.length) {
	resource += 'index.html';
    }
    if (resource == 'edit') {
	if (req.user) {
	    var slides=null;
	    if (req.body.presentation)
		slides = req.user.presentations[req.body.presentation].slides;
	    res.render('edit.jade', {'slides': [slides]});
	} else
	    res.redirect('/');
    } else if (resource == 'new') {
	if (req.user)
	    res.render('new.jade');
	else
	    res.redirect('/');
    } else {
	next();
    }
});

app.use(express.static(__dirname + '/public'));

app.listen(4012);