const mongoose = require('mongoose');

const ListingSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  price: Number,
  category: String,
  seller: String,
  photo: String, // e.g., '/Asset/images/CampusConnectLogo.png' or URL
  condition: String
});

module.exports = mongoose.model('Listing', ListingSchema);
