require('dotenv').config();
const mongoose = require('mongoose');
const Listing = require('../server/models/Listing');
const Service = require('../server/models/Service');
const Event = require('../server/models/Event');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/campusmarketplace';

async function seed() {
  await mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('Connected to MongoDB for seeding');

  // Sample Listings
  const listings = [
    {
      title: 'Calculus Textbook - 2nd Edition',
      description: 'Well-kept calculus textbook, some highlighting but fully usable.',
      price: 30,
      seller: 'John D.',
      category: 'Books',
      condition: 'Good',
      image: '/Asset/images/placeholder.jpg',
      contact: 'john@example.com'
    },
    {
      title: 'MacBook Charger (60W)',
      description: 'Original Apple charger in perfect condition.',
      price: 25,
      seller: 'Alice S.',
      category: 'Electronics',
      condition: 'Like New',
      image: '/Asset/images/placeholder.jpg',
      contact: 'alice@example.com'
    },
    {
      title: 'Dorm Desk Lamp',
      description: 'LED desk lamp with adjustable brightness.',
      price: 10,
      seller: 'Mark T.',
      category: 'Furniture',
      condition: 'Good',
      image: '/Asset/images/placeholder.jpg',
      contact: 'mark@example.com'
    }
  ];

  // Sample Services
  const services = [
    {
      title: 'Physics Tutoring - First Year',
      description: 'I can help with mechanics and basic E&M. Flexible times.',
      category: 'Tutoring',
      rate: '$25/hr',
      contact: 'tutor1@example.com',
      providerName: 'Sara P.'
    },
    {
      title: 'Group Study - CS Introduction',
      description: 'Weekly study group for CS101, exercises and exam prep.',
      category: 'Other',
      rate: 'Free',
      contact: 'studygroup@example.com',
      providerName: 'CS Club'
    }
  ];

  // Sample Events
  const now = new Date();
  const events = [
    {
      title: 'Resume Workshop',
      description: 'Learn how to write an effective resume for internships.',
      date: new Date(now.getFullYear(), now.getMonth(), now.getDate() + 7),
      time: '18:00',
      location: 'STEM Building - Room 101',
      category: 'Career',
      contact: 'careers@example.com',
      organizerName: 'Career Services'
    },
    {
      title: 'Math Study Jam',
      description: 'Open drop-in session for calculus and linear algebra help.',
      date: new Date(now.getFullYear(), now.getMonth(), now.getDate() + 3),
      time: '16:00',
      location: 'Library - Study Room A',
      category: 'Academic',
      contact: 'mathdept@example.com',
      organizerName: 'Math Club'
    }
  ];

  try {
    await Listing.deleteMany({});
    await Service.deleteMany({});
    await Event.deleteMany({});

    const createdListings = await Listing.insertMany(listings);
    const createdServices = await Service.insertMany(services);
    const createdEvents = await Event.insertMany(events);

    console.log('Seeded listings:', createdListings.length);
    console.log('Seeded services:', createdServices.length);
    console.log('Seeded events:', createdEvents.length);
  } catch (err) {
    console.error('Seeding error', err);
  } finally {
    mongoose.disconnect();
  }
}

seed();
