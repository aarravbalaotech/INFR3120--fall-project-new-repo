const express = require('express');
const router = express.Router();
const User = require('../model/User');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/auth/login');
}

// Configure multer for profile picture uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, '../..', 'public/uploads/profiles');
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, 'profile_' + req.user._id + '_' + Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

router.get('/', isLoggedIn, async (req, res, next) => {
  try {
    const users = await User.find({});
    res.render('users/index', { title: 'Users', users });
  } catch (err) {
    next(err);
  }
});

router.get('/profile', isLoggedIn, async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);
    res.render('users/profile', { title: 'Your Profile', user: user });
  } catch (err) {
    next(err);
  }
});

// Upload profile picture
router.post('/profile/upload-picture', isLoggedIn, upload.single('profilePicture'), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const user = await User.findById(req.user._id);
    
    // Delete old profile picture if exists
    if (user.profilePicture) {
      const oldPath = path.join(__dirname, '../..', 'public', user.profilePicture);
      if (fs.existsSync(oldPath)) {
        fs.unlinkSync(oldPath);
      }
    }
    
    user.profilePicture = '/uploads/profiles/' + req.file.filename;
    user.updatedAt = new Date();
    await user.save();
    
    res.json({ success: true, profilePicture: user.profilePicture });
  } catch (err) {
    next(err);
  }
});

// Change username
router.post('/profile/change-username', isLoggedIn, async (req, res, next) => {
  try {
    const { currentPassword, newUsername } = req.body;
    
    if (!currentPassword || !newUsername) {
      return res.status(400).json({ error: 'Current password and new username are required' });
    }
    
    const user = await User.findById(req.user._id);
    
    // Authenticate with current password
    user.authenticate(currentPassword, (err, authenticatedUser, passwordErr) => {
      if (err || passwordErr || !authenticatedUser) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }
      
      // Check if new username already exists
      User.findOne({ username: newUsername }, async (err, existingUser) => {
        if (existingUser && existingUser._id.toString() !== user._id.toString()) {
          return res.status(400).json({ error: 'Username already taken' });
        }
        
        user.username = newUsername;
        user.updatedAt = new Date();
        await user.save();
        
        res.json({ success: true, message: 'Username changed successfully' });
      });
    });
  } catch (err) {
    next(err);
  }
});

// Change password
router.post('/profile/change-password', isLoggedIn, async (req, res, next) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'New passwords do not match' });
    }
    
    const user = await User.findById(req.user._id);
    
    // Authenticate with current password
    user.authenticate(currentPassword, async (err, authenticatedUser, passwordErr) => {
      if (err || passwordErr || !authenticatedUser) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }
      
      // Change password
      user.setPassword(newPassword, async (err) => {
        if (err) return next(err);
        
        user.updatedAt = new Date();
        await user.save();
        
        res.json({ success: true, message: 'Password changed successfully' });
      });
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;