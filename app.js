const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const passport = require('passport');
const User = require('./models/user');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');
require('dotenv').config();

mongoose.connect(
	`mongodb+srv://${process.env.ID}:${process.env.PASSWORD}@cluster0.b9kou.mongodb.net/authdb`,
	{
		useNewUrlParser: true,
		useFindAndModify: true,
		useUnifiedTopology: true,
		useCreateIndex: true,
	},
	function () {
		console.log('Connected to MongoDB server');
	}
);

//The following used middleware should be in this order
//#1
//using express-session
app.use(
	session({
		secret: process.env.SECRET,
		resave: false,
		saveUninitialized: false,
	})
);
//#2
//initializing passport
app.use(passport.initialize());
//#3
//using passport to deal with the sessions
app.use(passport.session());

//passport.js
require('./passport').auth(passport);

app.get('/', function (req, res) {
	res.render('home');
});

//register  get|post
app
	.route('/register')
	.get(checkNotAuthenticated, function (req, res) {
		res.render('register');
	})
	.post(function (req, res) {
		bcrypt.hash(req.body.password, 10, function (err, result) {
			if (!err) {
				User.findOne({ email: req.body.email }, function (err, foundUser) {
					if (!foundUser) {
						User.create(
							{ email: req.body.email, password: result },
							function (err) {
								if (err) {
									console.log(err);
								}
								if (!err) {
									passport.authenticate('local')(req, res, function () {
										res.redirect('/secrets');
									});
								}
							}
						);
					} else {
						res.json({ error: 'Duplicate', type: 'Email already exists' });
					}
				});
			}
		});
	});

//login  get|post
app
	.route('/login')
	.get(checkNotAuthenticated, function (req, res) {
		res.render('login');
	})
	.post(
		passport.authenticate('local', {
			failureRedirect: '/',
		}),
		function (req, res) {
			res.redirect('/secrets');
		}
	);

//submit  get|post
app
	.route('/submit')
	.get(checkAuthenticated, function (req, res) {
		res.render('submit', req.user);
	})
	.post(checkAuthenticated, function (req, res) {
		let { user } = req.user;

		User.updateOne(
			{ _id: user._id },
			{
				$set: {
					secrets: req.body.secret,
				},
			},
			function (err, check) {
				if (err) {
					console.log(err);
				}

				res.redirect('/secrets');
			}
		);
	});

app.get('/secrets', checkAuthenticated, function (req, res) {
	User.find({ secrets: { $ne: null } }, function (err, foundUser) {
		//write in note
		if (err) {
			console.log(err);
			return;
		}

		res.render('secrets', {
			usersWithSecrets: foundUser,
			currentLogged: req.user.user,
		});
	});
});
app.get('/logout', checkAuthenticated, function (req, res) {
	req.logout();
	res.redirect('/login');
});

//if we are logged out, do not allow secrets
function checkAuthenticated(req, res, next) {
	if (req.isAuthenticated()) {
		return next();
	}
	res.redirect('/login');
}

//if we are logged, do not allow login and register.
function checkNotAuthenticated(req, res, next) {
	if (!req.isAuthenticated()) {
		return next();
	}

	res.redirect('/secrets');
}

//google oauth2

//first goes to google ui and asks to login with one of the account and after checking api keys from the google it
//brings us back to /auth/google/callback with scope data
//passport then checks if the id exists or not based on that findOrCreate and passes the serialized data to session cookie
app.get(
	'/auth/google',
	passport.authenticate('google', { scope: ['email', 'profile'] }) //scope declaration as scpecified in google api
);

app.get(
	'/auth/google/secrets',
	passport.authenticate('google', { failureRedirect: '/login' }),
	function (req, res) {
		// Successful authentication, redirect dashboard.
		res.redirect('/secrets');
	}
);

//facebook
//same logic as google but during request what kind of scope is needed is also passed.
app.get(
	'/auth/facebook',
	passport.authenticate('facebook', { scope: ['email'] })
);

app.get(
	'/auth/facebook/secrets',
	passport.authenticate('facebook', {
		failureRedirect: '/login',
	}),
	function (req, res) {
		// Successful authentication, redirect home.
		res.redirect('/secrets');
	}
);
let PORT = process.env.PORT || process.env.MYPORT;
app.listen(PORT, function () {
	console.log('App is running on PORT ' + process.env.MYPORT);
});
