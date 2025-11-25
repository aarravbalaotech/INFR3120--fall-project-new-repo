require('dotenv').config();

const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const MongoStore = require('connect-mongo');
const flash = require('connect-flash');

const User = require('./server/model/User');

// Routes
const indexRouter = require('./server/routes/index');
const usersRouter = require('./server/routes/users');
const listingsRouter = require('./server/routes/listings');
const servicesRouter = require('./server/routes/services');
const eventsRouter = require('./server/routes/events');
const authRouter = require('./server/routes/auth');

const app = express();

// MongoDB connection is handled in `server.js` to keep startup responsibilities
// centralized. Do not connect here to avoid duplicate connections and double
// server.listen calls when `server.js` imports this module.

// ===== View Engine =====
app.set('views', path.join(__dirname, 'server', 'views'));
app.set('view engine', 'ejs');
app.set('view cache', false);

// ===== Middleware =====
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'node_modules')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/campusconnect',
    touchAfter: 24 * 3600
  }),
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// ===== Locals =====
app.use((req, res, next) => {
  res.locals.isAuthenticated = req.isAuthenticated();
  res.locals.displayName = req.user ? req.user.displayName : null;
  res.locals.user = req.user || null;
  res.locals.error = req.flash('error');
  next();
});

// ===== Routes =====
app.use('/auth', authRouter);
app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/listings', listingsRouter);
app.use('/services', servicesRouter);
app.use('/events', eventsRouter);

// ===== 404 =====
app.use((req, res, next) => next(createError(404)));

// ===== Error Handler =====
app.use((err, req, res, next) => {
  const isDev = req.app.get('env') === 'development';
  const errorLocals = isDev ? err : {};
  res.status(err.status || 500);
  res.render('error', {
    title: 'Error',
    message: err && err.message ? err.message : 'An error occurred',
    error: errorLocals
  });
});

module.exports = app;



