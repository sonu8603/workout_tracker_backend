const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const { 
  register, 
  login, 
  forgotPassword, 
  resetPassword,
  logout 
} = require('../controllers/authController');
const { protect } = require('../middleware/auth');

// Register route with validation
router.post(
  '/register',
  [
    body('username')
      .trim()
      .isLength({ min: 3 })
      .withMessage('Username must be at least 3 characters'),
    body('email')
      .isEmail()
      .normalizeEmail({ gmail_remove_dots: false })
      .withMessage('Please provide a valid email'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters'),
    body('phone')
      .optional()
      .trim()
      .matches(/^[0-9]{10}$/)
      .withMessage('Phone number must be 10 digits'),
  ],
  register
);

// Login route
router.post('/login', login);

// Forgot password route
router.post('/forgot-password', forgotPassword);

// Reset password route
router.put('/reset-password/:resetToken', resetPassword);

// Logout route (protected)
router.post('/logout', protect, logout);

module.exports = router;