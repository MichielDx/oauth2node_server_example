var JWT = require('jsonwebtoken');

var model = module.exports;

var JWT_ISSUER = 'oauth2_id';
var JWT_SECRET_FOR_ACCESS_TOKEN = 'mySecret';
var JWT_SECRET_FOR_REFRESH_TOKEN = 'mySecret';

// the expiry times should be consistent between the oauth2-server settings
// and the JWT settings (not essential, but makes sense)
model.JWT_ACCESS_TOKEN_EXPIRY_SECONDS = 10000;
model.JWT_REFRESH_TOKEN_EXPIRY_SECONDS = 30000;

// In-memory datastores
var oauthClients = [{
	clientId: 'trusted-app',
	clientSecret: 'secret'
}];

// key is grant_type
// value is the array of authorized clientId's
var authorizedClientIds = {
	password: [
		'trusted-app'
	],
	refresh_token: [
		'trusted-app'
	]
};

// current registered users
var users = [{
	username: 'admin',
	password: 'admin',
	authorities: ['ROLE_AUTHOR']
}];

// generateToken
// This generateToken implementation generates a token with JWT.
// the token output is the Base64 encoded string.
model.generateToken = function (type, req, callback) {
	var token;
	var secret;
	var user = req.user;
	var exp = new Date();
	var payload = {
		aud: [JWT_ISSUER],
		user_name: user.username,
		scope: ['read', 'write'],
		authorities: user.authorities,
		client_id: req.oauth.client.clientId
	};
	var options = {
		algorithms: ['HS256']  // HMAC using SHA-256 hash algorithm
	};

	if (type === 'accessToken') {
		secret = JWT_SECRET_FOR_ACCESS_TOKEN;
		exp.setSeconds(exp.getSeconds() + model.JWT_ACCESS_TOKEN_EXPIRY_SECONDS);
	} else {
		secret = JWT_SECRET_FOR_REFRESH_TOKEN;
		exp.setSeconds(exp.getSeconds() + model.JWT_REFRESH_TOKEN_EXPIRY_SECONDS);
	}
	payload.exp = exp.getTime();

	token = JWT.sign(payload, new Buffer(secret, 'base64'), options);

	callback(false, token);
};

// The bearer token is a JWT, so we decrypt and verify it. We get a reference to the
// user in this function which oauth2-server puts into the req object
model.getAccessToken = function (bearerToken, callback) {
	return JWT.verify(bearerToken, new Buffer(JWT_SECRET_FOR_ACCESS_TOKEN, 'base64'), function (err, decoded) {

		if (err) {
			return callback(err, false);   // the err contains JWT error data
		}

		// other verifications could be performed here
		// eg. that the jti is valid

		// we could pass the payload straight out we use an object with the
		// mandatory keys expected by oauth2-server, plus any other private
		// claims that are useful
		return callback(false, {
			expires: new Date(decoded.exp),
			user: getUserByUsername(decoded.user_name)
		});
	});
};


// As we're using JWT there's no need to store the token after it's generated
model.saveAccessToken = function (accessToken, clientId, expires, userId, callback) {
	return callback(false);
};

// The bearer token is a JWT, so we decrypt and verify it. We get a reference to the
// user in this function which oauth2-server puts into the req object
model.getRefreshToken = function (bearerToken, callback) {
	return JWT.verify(bearerToken, new Buffer(JWT_SECRET_FOR_REFRESH_TOKEN, 'base64'), function (err, decoded) {

		if (err) {
			return callback(err, false);
		}

		// other verifications could be performed here
		// eg. that the jti is valid

		// instead of passing the payload straight out we use an object with the
		// mandatory keys expected by oauth2-server plus any other private
		// claims that are useful
		return callback(false, {
			expires: new Date(decoded.exp),
			user: getUserByUsername(decoded.user_name),
			clientId: decoded.client_id
		});
	});
};

// required for grant_type=refresh_token
// As we're using JWT there's no need to store the token after it's generated
model.saveRefreshToken = function (refreshToken, clientId, expires, userId, callback) {
	return callback(false);
};

// authenticate the client specified by id and secret
model.getClient = function (clientId, clientSecret, callback) {
	for (var i = 0, len = oauthClients.length; i < len; i++) {
		var elem = oauthClients[i];
		if (elem.clientId === clientId &&
			(clientSecret === null || elem.clientSecret === clientSecret)) {
			return callback(false, elem);
		}
	}
	callback(false, false);
};

// determine whether the client is allowed the requested grant type
model.grantTypeAllowed = function (clientId, grantType, callback) {
	callback(false, authorizedClientIds[grantType] &&
		authorizedClientIds[grantType].indexOf(clientId.toLowerCase()) >= 0);
};

// authenticate a user
// for grant_type password
model.getUser = function (username, password, callback) {
	for (var i = 0, len = users.length; i < len; i++) {
		var elem = users[i];
		if (elem.username === username && elem.password === password) {
			return callback(false, elem);
		}
	}
	callback(false, false);
};

var getUserByUsername = function (username) {
	for (var i = 0, len = users.length; i < len; i++) {
		var elem = users[i];
		if (elem.username === username) {
			return elem;
		}
	}
	return null;
};