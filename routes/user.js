// ==================== CREATE FILE: routes/user.js ====================
const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const { 
  getProfile, 
  updateProfile,
  updateProfileImage,
  deleteAccount,
  getUserStats
} = require('../controllers/userController');
const { protect } = require('../middleware/auth');

// All routes are protected
router.use(protect);

// Validation for profile update
const updateProfileValidation = [
  body('username')
    .optional()
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be 3-30 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail({ gmail_remove_dots: false })
    .withMessage('Please provide a valid email'),
  body('phone')
    .optional()
    .trim()
    .matches(/^[0-9]{10}$/)
    .withMessage('Phone number must be 10 digits'),
  body('currentPassword')
    .optional()
    .notEmpty()
    .withMessage('Current password is required when changing password'),
  body('newPassword')
    .optional()
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters'),
];

// Routes
router.get('/profile', getProfile);
router.put('/profile', updateProfileValidation, updateProfile);
router.put('/profile-image', updateProfileImage);
router.delete('/account', deleteAccount);
router.get('/stats', getUserStats);

module.exports = router;