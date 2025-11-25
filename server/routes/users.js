const express = require('express');
const router = express.Router();

const User = require('../model/User');

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/auth/login');
}

router.get('/', isLoggedIn, async (req, res, next) => {
  try {
    const users = await User.find({});
    res.render('users/index', { title: 'Users', users });
  } catch (err) {
    next(err);
  }
});

router.get('/profile', isLoggedIn, (req, res) => {
  res.render('users/profile', { title: 'Your Profile', user: req.user });
});

module.exports = router;