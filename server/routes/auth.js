const express = require('express');
const router = express.Router();
const passport = require('passport');
const User = require('../model/User');

// ===== LOGIN =====
router.get('/login', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/');
  const errorMsg = req.flash('error')[0]; // get first error message
  res.render('login', { title: 'Login', error: errorMsg });
});

router.post('/login', passport.authenticate('local', {
  failureRedirect: '/auth/login',
  failureFlash: 'Invalid username or password'
}), (req, res) => {
  res.redirect('/');
});

// ===== REGISTER =====
router.get('/register', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/');
  const errorMsg = req.flash('error')[0]; // get first error message
  res.render('register', { title: 'Register', error: errorMsg });
});

router.post('/register', async (req, res, next) => {
  try {
    const { username, email, displayName, password, passwordConfirm } = req.body;

    if (!username || !email || !displayName || !password || !passwordConfirm) {
      req.flash('error', 'Please fill in all required fields');
      return res.redirect('/auth/register');
    }

    if (password !== passwordConfirm) {
      req.flash('error', 'Passwords do not match');
      return res.redirect('/auth/register');
    }

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      req.flash('error', 'Username or email already in use');
      return res.redirect('/auth/register');
    }

    const newUser = new User({ username, email, displayName });
    User.register(newUser, password, (err, user) => {
      if (err) {
        req.flash('error', err.message || 'Error creating account');
        return res.redirect('/auth/register');
      }

      req.logIn(user, (err) => {
        if (err) return next(err);
        res.redirect('/');
      });
    });
  } catch (err) {
    next(err);
  }
});

// ===== LOGOUT =====
router.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.redirect('/');
  });
});

module.exports = router;

