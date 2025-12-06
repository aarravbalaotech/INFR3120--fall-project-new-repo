const express = require('express');
const router = express.Router();
const passport = require('passport');
const User = require('../model/User');

//  LOGIN 
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

//  REGISTER 
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

//  LOGOUT 
router.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.redirect('/');
  });
});

//  GOOGLE OAUTH 
router.get('/google', passport.authenticate('google', {
  scope: ['profile', 'email']
}));

router.get('/google/callback', passport.authenticate('google', {
  failureRedirect: '/auth/login',
  failureFlash: 'Google authentication failed'
}), (req, res) => {
  res.redirect('/');
});

//  GITHUB OAUTH 
router.get('/github', passport.authenticate('github', {
  scope: ['user:email']
}));

router.get('/github/callback', passport.authenticate('github', {
  failureRedirect: '/auth/login',
  failureFlash: 'GitHub authentication failed'
}), (req, res) => {
  res.redirect('/');
});

//  OAUTH LINKING FOR AUTHENTICATED USERS
// Link Google OAuth to existing profile
router.get('/link/google', (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/auth/login');
  }
  // Check if Google is already connected
  User.findById(req.user._id, (err, user) => {
    if (err) return next(err);
    if (user && user.googleId) {
      return res.redirect('/users/profile?message=google_already_connected');
    }
    // Proceed with Google auth
    passport.authenticate('google', {
      scope: ['profile', 'email']
    })(req, res, next);
  });
});

router.get('/link/google/callback', passport.authenticate('google', {
  failureRedirect: '/users/profile',
  failureFlash: 'Google authentication failed'
}), async (req, res, next) => {
  try {
    // If already authenticated, link the Google ID to the existing user
    if (req.user && req.user._id) {
      const user = await User.findById(req.user._id);
      if (user) {
        user.googleId = req.user.googleId || req.user.id;
        if (!user.authProvider || user.authProvider === 'local') {
          user.authProvider = 'google';
        }
        await user.save();
      }
    }
    res.redirect('/users/profile?message=google_connected');
  } catch (err) {
    next(err);
  }
});

// Link GitHub OAuth to existing profile
router.get('/link/github', (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/auth/login');
  }
  // Check if GitHub is already connected
  User.findById(req.user._id, (err, user) => {
    if (err) return next(err);
    if (user && user.githubId) {
      return res.redirect('/users/profile?message=github_already_connected');
    }
    // Proceed with GitHub auth
    passport.authenticate('github', {
      scope: ['user:email']
    })(req, res, next);
  });
});

router.get('/link/github/callback', passport.authenticate('github', {
  failureRedirect: '/users/profile',
  failureFlash: 'GitHub authentication failed'
}), async (req, res, next) => {
  try {
    // If already authenticated, link the GitHub ID to the existing user
    if (req.user && req.user._id) {
      const user = await User.findById(req.user._id);
      if (user) {
        user.githubId = req.user.githubId || req.user.id;
        if (!user.authProvider || user.authProvider === 'local') {
          user.authProvider = 'github';
        }
        await user.save();
      }
    }
    res.redirect('/users/profile?message=github_connected');
  } catch (err) {
    next(err);
  }
});

module.exports = router;

