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
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
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

// ===== Passport Strategies =====
// Local Strategy
passport.use(new LocalStrategy(User.authenticate()));

// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URI || '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Try to find user by Google ID
    let user = await User.findOne({ googleId: profile.id });
    
    if (user) {
      return done(null, user);
    }
    
    // Check if email already exists
    const existingEmail = await User.findOne({ email: profile.emails[0].value });
    if (existingEmail) {
      // Only link if Google ID is not already set
      if (!existingEmail.googleId) {
        existingEmail.googleId = profile.id;
        if (existingEmail.authProvider === 'local') {
          existingEmail.authProvider = 'google';
        }
        await existingEmail.save();
      }
      return done(null, existingEmail);
    }
    
    // Create new user (only set fields that have values)
    const newUserData = {
      email: profile.emails[0].value,
      displayName: profile.displayName,
      authProvider: 'google',
      username: profile.id
    };
    
    if (profile.id) {
      newUserData.googleId = profile.id;
    }
    
    const newUser = new User(newUserData);
    await newUser.save();
    done(null, newUser);
  } catch (err) {
    done(err);
  }
}));

// GitHub Strategy
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: process.env.GITHUB_CALLBACK_URI || '/auth/github/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Try to find user by GitHub ID
    let user = await User.findOne({ githubId: profile.id });
    
    if (user) {
      return done(null, user);
    }
    
    // Check if email already exists
    const userEmail = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
    if (userEmail) {
      const existingEmail = await User.findOne({ email: userEmail });
      if (existingEmail) {
        // Only link if GitHub ID is not already set
        if (!existingEmail.githubId) {
          existingEmail.githubId = profile.id;
          if (existingEmail.authProvider === 'local') {
            existingEmail.authProvider = 'github';
          }
          await existingEmail.save();
        }
        return done(null, existingEmail);
      }
    }
    
    // Create new user (only set fields that have values)
    const newUserData = {
      displayName: profile.displayName || profile.username,
      authProvider: 'github',
      username: profile.username
    };
    
    if (profile.id) {
      newUserData.githubId = profile.id;
    }
    
    if (userEmail) {
      newUserData.email = userEmail;
    } else {
      newUserData.email = `${profile.username}@github.local`;
    }
    
    const newUser = new User(newUserData);
    await newUser.save();
    done(null, newUser);
  } catch (err) {
    done(err);
  }
}));

// Serialization
passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const mongoose = require('mongoose');
    let user = null;

    // If id looks like an ObjectId, use findById. Otherwise try legacy/session values (username, provider ids, email)
    if (mongoose.Types.ObjectId.isValid(id)) {
      user = await User.findById(id);
    }

    if (!user) {
      user = await User.findOne({
        $or: [
          { username: id },
          { googleId: id },
          { githubId: id },
          { email: id }
        ]
      });
    }

    done(null, user);
  } catch (err) {
    done(err);
  }
});

// ===== Locals =====
app.use((req, res, next) => {
  res.locals.isAuthenticated = req.isAuthenticated();
  res.locals.displayName = req.user ? req.user.displayName : null;
  res.locals.user = req.user || null;
  // Don't consume flash messages here - let routes handle them
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

// ===== Error Handler ===== please work 
app.use((err, req, res, next) => {
  const isDev = req.app.get('env') === 'development';
  const errorLocals = isDev ? err : {};
  // Ensure  the auth/local variables available even during errors
  try {
    res.locals.isAuthenticated = typeof req.isAuthenticated === 'function' ? req.isAuthenticated() : false;
    res.locals.displayName = req.user ? req.user.displayName : null;
    res.locals.user = req.user || null;
  } catch (e) {
    // ignore
  }

  // Log the error stack to the console for debugging
  console.error('Unhandled error:', err && err.stack ? err.stack : err);

  res.status(err.status || 500);
  res.render('error', {
    title: 'Error',
    message: err && err.message ? err.message : 'An error occurred',
    error: errorLocals
  });
});

module.exports = app;



