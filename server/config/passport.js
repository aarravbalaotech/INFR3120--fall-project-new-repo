/**
 * Passport Authentication Configuration
 * File: server/config/passport.js
 * Purpose: Setup Passport.js local strategy and user serialization
 */

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../model/User');

/**
 * Configure Local Strategy
 * Uses username and passport-local-mongoose plugin for password verification
 */
passport.use(new LocalStrategy(
  {
    usernameField: 'username',
    passwordField: 'password'
  },
  User.authenticate()
));

/**
 * Serialize user for session storage
 */
passport.serializeUser(User.serializeUser());

/**
 * Deserialize user from session storage
 */
passport.deserializeUser(User.deserializeUser());

module.exports = passport;
