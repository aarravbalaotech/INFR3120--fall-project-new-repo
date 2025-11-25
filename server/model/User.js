const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    unique: true,
    sparse: true,
    required: true
  },
  email: {
    type: String,
    unique: true,
    sparse: true,
    required: true,
    lowercase: true,
    trim: true
  },
  displayName: {
    type: String,
    required: true,
    trim: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Apply passport-local-mongoose plugin
// This automatically adds password hashing, serialization, and authentication methods
userSchema.plugin(passportLocalMongoose, {
  usernameField: 'username',
  usernameLowerCase: true,
  saltlen: 10
});

module.exports = mongoose.model('User', userSchema);
