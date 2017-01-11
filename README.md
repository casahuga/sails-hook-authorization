This lib heavily reused code from sails-hook-authorization library but the bcrypt library was change to https://github.com/shaneGirish/bcrypt-nodejs which one can we used in windows platforms.

# sails-hook-authorization
Hook that provides jwt authentication sails-compatible scheme, such as policies, routes, controllers, services.
Based on https://github.com/saviogl/sails-hook-jwt-auth

# Installation

```javascript
npm install sails-hook-authorization-bcrypt-nodejs --save
```

# Service
This module globally expose a service which integrates with the jsonwebtoken (https://github.com/auth0/node-jsonwebtoken) and provide the interface to apply the jwt specification (http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html).

```javascript
module.exports.validatePassword = function(currentPassword, oldPassword) {
  return Promise.resolve(true);
};

module.exports.findAccessToken = function(req) {
  return accessToken;
};

module.exports.issueTokenForUser = function(user) {
  return token;
};

module.exports.issueToken = function(payload, options) {
  return token
};

module.exports.verifyToken = function(token) {
  return Promise.resolve(token);
};

module.exports.decodeToken = function(token, options) {
  return decodedToken;
};

module.exports.refreshToken = function(decodedToken, expiresIn) {
  return Promise.resolve(token);
};

module.exports.issueRefreshTokenForUser = function(token) {
  return token;
};

// renews the `access_token` based on the `refresh_token`
module.exports.validateRefreshToken = function(accessToken, refreshToken) {
  return Promise.resolve(tokens);
};

// set the token payload issued by login
module.exports.payloadBuilder = function (user, payload) {
  payload.foo = 'bar';

  return payload;
}
```

## payloadBuilder()
It's possible to override `payloadBuilder()` with your own function. This allows you to extend/populate the token payload with custom data or logic.

### properties
You can extend the token payload by giving setting `sails.config.auth.jwt.payloadProperties`. The user object is used to populate the properties.

Example:
```js
  let properties = ['disabled', {groups: 'id'}];

  return {
    user    : user.id,       // default
    username: user.username, // default
    disabled: user.disabled,
    groups  : [3, 4, 6] // get the id's from an array with objects
  }
```


# Policy
The `verifyToken.js` and `ensureToken.js` policies are just like any other Sails policy and can be applied as such. It's responsible for parsing the token from the incoming request and validating it's state.

Use it as you would use any other sails policy to enable authentication restriction to your `Controllers/Actions`:

```javascript
module.exports.policies = {
  ...
  'AuthController': ['verifyToken', 'ensureToken'],
  ...
};
```

# Model
This hook sets up a basic `User` model with some defaults attributes required to implement the jwt authentication
scheme such as `username`, `email` and `emailConfirmed`. The `User` model can be extended with any property you want by defining it in your own Sails project.

# Routes
These are the routes provided by this hook:

```javascript
module.exports.routes = {
  'POST /login'                  : 'AuthController.login',
  'POST /signup'                 : 'AuthController.signup',
  'GET /auth/verify-email/:token': 'AuthController.verifyEmail',
  'GET /auth/me'                 : 'AuthController.me',
  'POST /auth/refresh-token'     : 'AuthController.refreshToken'
};
```

## POST /auth/login
The request to this route `/auth/login` must be sent with these body parameters:

```javascript
{
  email   : 'email@test.com', // or username based on the `loginProperty`
  password: 'test123'
}
```

The response:

```javascript
{
  access_token : 'jwt_access_token',
  refresh_token: 'jwt_refresh_token'
}
```

Make sure that you provide the acquired token in every request made to the protected endpoints, as query parameter `access_token` or as an HTTP request `Authorization` header `Bearer TOKEN_VALUE`.

The default TTL of the `access_token` is 1 day, `refresh_token` is 30 days.
If the `access_token` is expired you can expect the `expired_token` error.


## POST /auth/signup
The request to this route `/signup` must be sent with these body parameters:

```javascript
{
  username       : 'test',
  email          : 'email@test.com',
  password       : 'test123'
}
```

If the email verification feature is disabled, the response will be the same as the `/auth/login`.

```javascript
{
  access_token : 'new jwt access token',
  refresh_token: 'new jwt refresh token'
}
```

If it's enabled you will get a 200 as response:

## GET /auth/activate/:token
### Account Activation
This feature is off by default and to enable it you must override the `requireEmailVerification` configuration and implement the function `sendVerificationEmail`:

```javascript
module.exports.auth = {
  secret                  : process.env.JWT_SECRET || 'superSecretForDev',
  loginProperty           : 'email',
  requireEmailVerification: false,
  sendVerificationEmail   : (user, activateUrl) => {
    sails.log.error('sails-hook-authorization:: An email function must be implemented through `sails.config.auth.sendVerificationEmail` in order to enable the email verification feature. This will receive two parameters (user, activationLink).');
  },

  // seconds to be valid
  ttl: {
    accessToken : process.env.JWT_TOKEN_TTL || 86400,  // 1 day
    refreshToken: process.env.JWT_REFRESH_TOKEN_TTL || 2592000 // 30 days
  }
};

```

## GET /auth/me
Returns the user, token protected area.

## POST /auth/refresh-token
Refreshes the `access_token` based on the `refresh_token`.
If the `refresh_token` is expired it will return `expired_refresh_token` and the user must login through `/login`

The request:

```javascript
{
  access_token : 'jwt access token',
  refresh_token: 'jwt refresh token'
}
```

The response:

```javascript
{
  access_token : 'new jwt access token',
  refresh_token: 'new jwt refresh token'
}
```
