var bcrypt = require('bcrypt-nodejs');

module.exports = {
  attributes: {
    username: {
      type : 'string',
      index: true
    },

    email: {
      type : 'email',
      index: true
    },

    password: {
      type    : 'string',
      required: true
    },

    emailConfirmed: {
      type      : 'boolean',
      defaultsTo: false
    },

    toJSON: function() {
      var values = this.toObject();

      delete values.password;

      return values;
    }
  },

  beforeCreate: encryptPassword,
  beforeUpdate: (values, next) => {
    if (!values.password) {
      delete values.password;

      return next();
    }

    try {
      // check if the password is already hashed
      if (isNaN(bcrypt.getRounds(values.password))) {
        return encryptPassword(values, next);
      }
    } catch(e) {
      return encryptPassword(values, next);
    }

    next();
  }
};

function encryptPassword(values, next) {
  if (!values.password) {
    return next();
  }

  bcrypt.genSalt(10, function (err, reply) {
    if (err) { return err }      
    salt = reply;
  })
  bcrypt.hash(values.password, salt, null, function (error, hash) {
    if (error) {
      return next(error);
    }

    values.password = hash;

    next();
  });
}
