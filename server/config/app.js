require('dotenv').config();

var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const MongoStore = require('connect-mongo');
const User = require('./server/models/User');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var listingsRouter = require('./routes/listings');
const servicesRouter = require('./routes/services');
const eventsRouter = require('./routes/events');
const authRouter = require('./routes/auth');


var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'node_modules')));

// ===== SESSION & PASSPORT SETUP =====
// Configure session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  store: new MongoStore({
    mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/campusmarketplace',
    touchAfter: 24 * 3600 // lazy session update in seconds
  }),
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    maxAge: 1000 * 60 * 60 * 24 * 7 // 1 week
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Configure Passport strategy (uses passport-local-mongoose plugin methods)
passport.use(new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password'
}, User.authenticate()));

// Serialize user to session
passport.serializeUser(User.serializeUser());

// Deserialize user from session
passport.deserializeUser(User.deserializeUser());

// Middleware to expose authentication info to all views
app.use((req, res, next) => {
  res.locals.isAuthenticated = req.isAuthenticated();
  res.locals.displayName = req.user ? req.user.displayName : null;
  res.locals.user = req.user || null;
  next();
});

// ===== ROUTE HANDLERS =====
app.use('/auth', authRouter);
app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/listings', listingsRouter);
app.use('/services', servicesRouter);
app.use('/events', eventsRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // Provide error details to the template (only show stack/details in development)
  const isDev = req.app.get('env') === 'development';
  const errorLocals = isDev ? err : {};

  // render the error page with explicit locals so the template won't see undefined values
  res.status(err.status || 500);
  res.render('error', {
    title: 'Error',
    message: err && err.message ? err.message : 'An error occurred',
    error: errorLocals
  });
});

module.exports = app;
