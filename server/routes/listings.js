var express = require('express');
var router = express.Router();
var Listing = require('../model/Listing');

/* GET Listings - View all listings with optional filter/search */
router.get('/', async function(req, res, next) {
  try {
    const filter = {};
    
    // Filter by category if provided
    if (req.query.category) {
      filter.category = req.query.category;
    }
    
    // Search by title if provided
    if (req.query.search) {
      filter.title = { $regex: req.query.search, $options: 'i' };
    }
    
    // Only show active listings
    filter.active = true;
    
    const listings = await Listing.find(filter).sort({ createdAt: -1 });
    
    res.render('projects', {
      title: 'Marketplace',
      listings: listings,
      selectedCategory: req.query.category || '',
      searchQuery: req.query.search || ''
    });
  } catch (err) {
    next(err);
  }
});

/* GET Create Listing Form */
router.get('/new', function(req, res, next) {
  res.render('create-listing', { title: 'Create New Listing' });
});

/* GET Single Listing */
router.get('/:id', async function(req, res, next) {
  try {
    const listing = await Listing.findById(req.params.id);
    if (!listing) {
      return res.status(404).render('error', { title: 'Not Found', message: 'Listing not found' });
    }
    res.render('listing-detail', { title: listing.title, listing: listing });
  } catch (err) {
    next(err);
  }
});

/* GET Edit Listing Form */
router.get('/:id/edit', async function(req, res, next) {
  try {
    const listing = await Listing.findById(req.params.id);
    if (!listing) {
      return res.status(404).render('error', { title: 'Not Found', message: 'Listing not found' });
    }
    res.render('edit-listing', { title: 'Edit Listing', listing: listing });
  } catch (err) {
    next(err);
  }
});

/* POST Create Listing */
router.post('/', async function(req, res, next) {
  try {
    const listing = new Listing(req.body);
    await listing.save();
    res.redirect('/listings');
  } catch (err) {
    let errorMsg = 'Please fill in all required fields.';
    // If it's not a validation error, show the actual error
    if (!err.name || err.name !== 'ValidationError') {
      errorMsg = err.message;
    }
    res.status(400).render('create-listing', {
      title: 'Create New Listing',
      error: errorMsg
    });
  }
});

/* POST Update Listing */
router.post('/:id/update', async function(req, res, next) {
  try {
    const listing = await Listing.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    if (!listing) {
      return res.status(404).render('error', { title: 'Not Found', message: 'Listing not found' });
    }
    res.redirect('/listings/' + req.params.id);
  } catch (err) {
    const listing = await Listing.findById(req.params.id);
    res.status(400).render('edit-listing', {
      title: 'Edit Listing',
      listing: listing,
      error: err.message
    });
  }
});

/* POST Delete Listing */
router.post('/:id/delete', async function(req, res, next) {
  try {
    const listing = await Listing.findByIdAndDelete(req.params.id);
    if (!listing) {
      return res.status(404).render('error', { title: 'Not Found', message: 'Listing not found' });
    }
    res.redirect('/listings');
  } catch (err) {
    next(err);
  }
});

module.exports = router;
