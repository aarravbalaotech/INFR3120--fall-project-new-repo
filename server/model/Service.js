const mongoose = require('mongoose');

const serviceSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  description: { type: String, required: true, trim: true },
  category: {
    type: String,
    enum: ['Tutoring', 'Roommate Find', 'Carpool', 'Printing', 'Tech Help', 'Other'],
    required: true
  },
  rate: { type: String, trim: true },
  contact: { type: String, required: true, trim: true },
  providerName: { type: String, required: true, trim: true },
  providerAvatar: { type: String, default: '' },
  image: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Service', serviceSchema);
