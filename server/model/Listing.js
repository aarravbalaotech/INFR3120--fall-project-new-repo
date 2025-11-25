const mongoose = require('mongoose');

const listingSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true,
    trim: true
  },
  price: {
    type: Number,
    required: true,
    min: 0
  },
  seller: {
    type: String,
    required: true,
    trim: true
  },
  category: {
    type: String,
    enum: ['Electronics', 'Books', 'Furniture', 'Clothing', 'Sports', 'Services', 'Other'],
    default: 'Other'
  },
  condition: {
    type: String,
    enum: ['New', 'Like New', 'Good', 'Fair'],
    default: 'Good'
  },
  image: {
    type: String,
    default: '/Asset/images/placeholder.jpg'
  },
  contact: {
    type: String,
    required: true
  },
  location: {
    type: String,
    default: 'Ontario Tech University'
  },
  active: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Listing', listingSchema);
