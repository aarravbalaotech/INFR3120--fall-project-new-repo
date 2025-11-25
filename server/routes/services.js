const express = require('express');
const router = express.Router();
const Service = require('../model/Service');
const multer = require('multer');
const upload = multer({ dest: 'public/uploads/' });

/* GET all services with optional filter/search */
router.get('/', async (req, res, next) => {
  try {
    const filter = {};
    if (req.query.category) filter.category = req.query.category;
    if (req.query.search) filter.title = { $regex: req.query.search, $options: 'i' };
    const services = await Service.find(filter).sort({ createdAt: -1 });
    res.render('services', { title: 'Campus Services', services: services });
  } catch (err) {
    next(err);
  }
});

/* GET offer service form */
router.get('/offer', (req, res) => {
  res.render('offer-service', { title: 'Offer a Service' });
});

/* POST create new service */
router.post('/offer', upload.single('image'), async (req, res, next) => {
  try {
    const serviceData = req.body;
    if (req.file) {
      serviceData.image = '/uploads/' + req.file.filename;
    }
    const service = new Service(serviceData);
    await service.save();
    res.redirect('/services');
  } catch (err) {
    res.status(400).render('offer-service', {
      title: 'Offer a Service',
      error: 'Please fill in all required fields.'
    });
  }
});

/* GET single service */
router.get('/:id', async (req, res, next) => {
  try {
    const service = await Service.findById(req.params.id);
    if (!service) return res.status(404).render('error', { message: 'Service not found.' });
    res.render('service-detail', { title: service.title, service: service });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
// });

module.exports = router;