const mongoose = require('mongoose');

//automatically encrypts and decrypts on create/save and find/query
const userSchema = new mongoose.Schema({
	email: { type: String, required: true },
	password: { type: String },
	googleId: { type: String },
	facebookId: { type: String },
	secrets: { type: String },
});

module.exports = mongoose.model('User', userSchema);
