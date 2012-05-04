var fs = require('fs')
  , crypto = require('crypto')
  , express = require('express')
  , punch = require('punch')
  , everyauth = require('everyauth')
  , jade = require('jade')
  , passhash = require('password-hash')
  , Recaptcha = require('recaptcha').Recaptcha
  , localcaptcha = require('./captcha.js')
  , publiccaptchakey = localcaptcha.publickey
  , privatecaptchakey = localcaptcha.privatekey
  , app = require('express').createServer();

var alphanum = new RegExp('^[A-Za-z0-9]+$');

everyauth.debug = true;

var nano = require('nano')('http://localhost:5984');
var db = nano.use('pressiv');
var dbobj;
db.get('pressiv_users', function (err, body) {
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
    .registerLocals( function(req, res) {
	var recaptcha = new Recaptcha(publiccaptchakey, privatecaptchakey);
	return { recaptcha_form: recaptcha.toHTML() };
    })
    .extractExtraRegistrationParams( function(req) {
	return { remoteip: req.connection.remoteAddres,
		 captchachallenge: req.body.recaptcha_challenge_field,
		 captcharesponse: req.body.recaptcha_response_field };
    })
    .validateRegistration( function (newUserAttrs) {
	var promise = this.Promise();
	var errors = [];
	var login = newUserAttrs.login;
	if (!login.match(alphanum)) errors.push('Login must be alphanumeric');
	if (login.length < 5) errors.push('Login must be at least 5 characters long');
	if (checkForLogin(login)) errors.push('Login already taken');
	var captchadata = { remoteip: newUserAttrs.remoteip,
			    challenge: newUserAttrs.captchachallenge,
			    response: newUserAttrs.captcharesponse };
	recaptcha = new Recaptcha(publiccaptchakey, privatecaptchakey, captchadata);
	recaptcha.verify(function (success, error_code) {
	    if (success) { promise.fulfill(); }
	    else { errors.push('Recaptcha is invalid'); console.log("Invalid captcha!"); promise.fulfill(errors); }
	});
	return promise;
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
    if (!req.user) {
	res.redirect('/');
	return;
    }
    if (!name.match(alphanum)) {
	res.render('new.jade', {'errors': ['Presentation name must be alphanumeric']});
	return;
    }
    var presentations = dbobj.users[req.user.id].presentations;
    var exist = false;
    if (typeof(presentations[name]) != "undefined")
	exist = true;
    if (exist) {
	res.render('new.jade', {'errors': ['You already have a presentation with that name']});
	return;
    }
    newpres = new Object;
    newpres.name = name;
    newpres.slides = new Array;
    presentations[name] = newpres;
    makeDirectories(req.user.login + '/' + name);
    db.insert(dbobj, 'pressiv_users', insertCallback);
    res.redirect('/edit?presentation=' + name);
});

app.post('/edit', function(req, res, next) {
    var jsonasstring = "";
    req.on('data', function(stuff) {
	jsonasstring += stuff.toString();
	try {
	    var jsontouse = JSON.parse(jsonasstring);
	    dbobj.users[req.user.id].presentations[jsontouse.name] = jsontouse;
	    db.insert(dbobj, 'pressiv_users', insertCallback);
	    fs.writeFile(__dirname + "/contents/" + req.user.login + "/" + jsontouse.name + "/index.json", JSON.stringify(jsontouse), function(err) {
		if (err) throw err;
		else console.log("Saved index.json in " + __dirname + "/contents/" + req.user.login + "/" + jsontouse.name + "/index.json");
	    });
	    punchconf = new Object;
	    punchconf.template_dir = "templates";
	    console.log("Template dir is "+punchconf.template_dir);
	    punchconf.content_dir = __dirname + "/contents/" + req.user.login + "/" + jsontouse.name;
	    console.log("Content dir is "+punchconf.content_dir);
	    punchconf.output_dir = __dirname + "/public/" + req.user.login + "/" + jsontouse.name;
	    console.log("Output dir is "+punchconf.output_dir);
	    punch.generate(punchconf);
	    res.send('/' + req.user.login + '/' + jsontouse.name);
	} catch (SyntaxError) {
	    console.log(SyntaxError);
	}
    });
});

app.get('/*', function(req, res, next) {
    var resource = req.params[0];
    if (resource.lastIndexOf('/') + 1 == resource.length) {
	resource += 'index.html';
    }
    if (resource == 'edit') {
	if (req.user) {
	    var slides=null;
	    if (req.query.presentation)
		slides = req.user.presentations[req.query.presentation].slides;
	    console.log(slides);
	    res.render('edit.jade', {'slides': JSON.stringify(slides), 'name': '"' + req.query.presentation + '"'});
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