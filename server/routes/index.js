var express = require('express');
var router = express.Router();
const Listing = require('../model/Listing');
const Service = require('../model/Service');
const Event = require('../model/Event');

/* GET home page with featured items. */
router.get('/', async function(req, res, next) {
  try {
    // Featured listings: most recent active listings (limit 6)
    const listings = await Listing.find({ active: true }).sort({ createdAt: -1 }).limit(6).lean();

    // Upcoming events: events on or after today, sorted by date asc (limit 6)
    const today = new Date();
    const events = await Event.find({ date: { $gte: today } }).sort({ date: 1 }).limit(6).lean();

    // Recent services (limit 6)
    const services = await Service.find({}).sort({ createdAt: -1 }).limit(6).lean();

    res.render('index', { title: 'Home', listings, events, services });
  } catch (err) {
    next(err);
  }
});

/* GET home alias. */
router.get('/home', function(req, res, next) {
  res.redirect('/');
});

/* GET About page. */
router.get('/about', function(req, res, next) {
  res.render('about', { title: 'About us' });
});

/* GET Contact page. */
router.get('/contactme', function(req, res, next) {
  res.render('index', { title: 'Contact us' });
});

module.exports = router;
