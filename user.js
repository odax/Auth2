const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    lowercase: true, // Kyle => kyle
  },
  password: {
    type: String,
    required: true,
    minlength: 5,
  },
});

userSchema.pre('save', function(next) {
  return bcrypt
    .hash(this.password, 10)
    .then(hash => {
      this.password = hash;

      return next();
    })
    .catch(err => {
      return next(err);
    });
});

// userSchema.methods.isPasswordValid = function(passwordGuess) {
//   //return a promise that comes out of bcrypt that compares
//   return bcrypt.compare(passwordGuess, this.password);
// };

userSchema.methods.validatePassword = function(passwordGuess) {
  return bcrypt.compare(passwordGuess, this.password);
};

module.exports = mongoose.model('User', userSchema);