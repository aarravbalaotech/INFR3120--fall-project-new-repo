var express = require('express');
var router = express.Router();
const Event = require('../model/Event');

/* GET events page. */
router.get('/', function(req, res, next) {
  Event.find({})
    .then(events => {
      res.render('events', { title: 'Campus Events', events: events });
    })
    .catch(err => next(err));
});

/* GET offer event form. */
router.get('/offer', function(req, res, next) {
  res.render('offer-event', { title: 'Create Event' });
});

/* POST create event. */
router.post('/offer', function(req, res, next) {
  const { title, description, date, time, location, category, contact, organizerName } = req.body;

  if (!title || !description || !date || !time || !location || !category || !contact || !organizerName) {
    return res.status(400).render('offer-event', {
      title: 'Create Event',
      error: 'Please fill in all required fields.'
    });
  }

  const newEvent = new Event({
    title,
    description,
    date,
    time,
    location,
    category,
    contact,
    organizerName
  });

  newEvent.save()
    .then(() => res.redirect('/events'))
    .catch(err => {
      res.status(400).render('offer-event', {
        title: 'Create Event',
        error: 'Please fill in all required fields.'
      });
    });
});

module.exports = router;