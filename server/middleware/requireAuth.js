/**
 * Middleware to protect routes and ensure user is authenticated
 * Use this on any route that requires login
 * 
 * Example:
 *   router.post('/listings', requireAuth, (req, res) => { ... })
 */

module.exports = function requireAuth(req, res, next) {
  // Check if user is authenticated
  if (req.isAuthenticated()) {
    // User is logged in, proceed to next middleware/route handler
    return next();
  }

  // User is NOT logged in
  // Check if this is an API request (JSON) or web request
  if (req.accepts('json')) {
    // API request: return 401 JSON error
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }

  // Web request: redirect to login page
  res.redirect('/auth/login');
};
