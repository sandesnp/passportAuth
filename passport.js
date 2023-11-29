const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const bcrypt = require('bcrypt');
const User = require('./models/user');
require('dotenv').config();

//Mongoose is already declared in app.js and User is already declared there as well
exports.auth = function (passport) {
	//local
	passport.use(
		new LocalStrategy(
			{ usernameField: 'email' }, //since i am providing 'email' and 'password' attribute from html form
			//usernameField default is 'username' and passwordField is 'password. Both gets passed to function below as parameter.
			function (email, password, done) {
				User.findOne({ email: email }, function (err, foundUser) {
					if (err) {
						return done(err);
					}
					if (!foundUser) {
						return done(null, false, { message: `username doesn't exist` });
					}
					bcrypt.compare(password, foundUser.password, function (err, result) {
						if (!result) {
							return done(null, false, { message: `username doesn't exist` });
						}
						return done(null, foundUser);
					});
				});
			}
		)
	);
	// passport(new Strategy(A,B));
	// A for requesting data which it saves
	// B for authenticating that requested than sending it to profile
	//google
	passport.use(
		new GoogleStrategy(
			{
				clientID: process.env.CLIENT_ID,
				clientSecret: process.env.CLIENT_SECRET,
				callbackURL: `${process.env.HOMEURL}/auth/google/secrets`,
			},
			function (accessToken, refreshToken, profile, done) {
				//gets gmail id and if doesn't exist creates one. The id gets seralized and put into session coookie

				User.findOne({ googleId: profile.id }, function (err, foundUser) {
					if (err) {
						return done(err);
					}
					if (!foundUser) {
						User.create(
							{ googleId: profile.id, email: profile.emails[0].value },
							function (err, user) {
								return done(err, user);
							}
						);
					} else {
						return done(err, foundUser);
					}
				});
			}
		)
	);

	//facebook
	passport.use(
		new FacebookStrategy(
			{
				clientID: process.env.APP_ID,
				clientSecret: process.env.APP_SECRET,
				callbackURL: `${process.env.HOMEURL}/auth/facebook/secrets`,
				//while we can specify scope in google console we cannot for facebook so we havee to pass request of what we need
				profileFields: ['id', 'emails', 'name'],
			},
			function (accessToken, refreshToken, profile, done) {
				//gets facebook id and if doesn't exist creates one. The id gets seralized and put into session coookie

				User.findOne({ facebookId: profile.id }, function (err, foundUser) {
					if (err) {
						return done(err);
					}
					if (!foundUser) {
						User.create(
							{ googleId: profile.id, email: profile.emails[0].value },
							function (err, user) {
								return done(err, user);
							}
						);
					} else {
						return done(err, foundUser);
					}
				});
			}
		)
	);

	passport.serializeUser(function (user, done) {
		done(null, user.id);
	});

	passport.deserializeUser(function (id, done) {
		User.findById(id, function (err, user) {
			done(err, { user });
		});
	});
};
