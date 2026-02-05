const User = require('../models/User');
const { validationResult } = require('express-validator');

/**
 * @desc    Get user profile
 * @route   GET /api/user/profile
 * @access  Private
 */
const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    res.status(200).json({
      success: true,
      ...user.toJSON(),
    });

  } catch (error) {
    console.error('❌ Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
};

/**
 * @desc    Update user profile
 * @route   PUT /api/user/profile
 * @access  Private
 */
const updateProfile = async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array().map(err => ({
          field: err.path,
          message: err.msg
        })),
      });
    }

    const { username, email, phone, currentPassword, newPassword } = req.body;

    // Find user with password field
    const user = await User.findById(req.user._id).select('+password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Check if trying to update username or email to existing value
    if (username && username !== user.username) {
      const usernameExists = await User.findOne({ username, _id: { $ne: user._id } });
      if (usernameExists) {
        return res.status(400).json({
          success: false,
          message: 'Username already taken',
          field: 'username'
        });
      }
      user.username = username.trim();
    }

    if (email && email.toLowerCase() !== user.email) {
      const emailExists = await User.findOne({ email: email.toLowerCase(), _id: { $ne: user._id } });
      if (emailExists) {
        return res.status(400).json({
          success: false,
          message: 'Email already registered',
          field: 'email'
        });
      }
      user.email = email.trim().toLowerCase();
      user.isEmailVerified = false; // Require re-verification
    }

    // Update phone if provided
    if (phone !== undefined) {
      user.phone = phone.trim();
    }

    // Handle password change
    if (currentPassword && newPassword) {
      // Verify current password
      const isPasswordCorrect = await user.comparePassword(currentPassword);
      
      if (!isPasswordCorrect) {
        return res.status(401).json({
          success: false,
          message: 'Current password is incorrect',
          field: 'currentPassword'
        });
      }

      // Validate new password
      if (newPassword.length < 6) {
        return res.status(400).json({
          success: false,
          message: 'New password must be at least 6 characters',
          field: 'newPassword'
        });
      }

      // Check if new password is same as current
      const isSamePassword = await user.comparePassword(newPassword);
      if (isSamePassword) {
        return res.status(400).json({
          success: false,
          message: 'New password must be different from current password',
          field: 'newPassword'
        });
      }

      user.password = newPassword;
      user.passwordChangedAt = Date.now();
    } else if (currentPassword || newPassword) {
      // If only one password field is provided
      return res.status(400).json({
        success: false,
        message: 'Both current password and new password are required to change password',
      });
    }

    // Save user
    await user.save();

    // Remove password from response
    const updatedUser = user.toJSON();

    console.log(`✅ Profile updated: ${user.email} (ID: ${user._id})`);

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      user: updatedUser,
    });

  } catch (error) {
    console.error('❌ Update profile error:', error);

    // Handle duplicate key errors
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return res.status(400).json({
        success: false,
        message: `${field.charAt(0).toUpperCase() + field.slice(1)} already exists`,
        field
      });
    }

    res.status(500).json({
      success: false,
      message: 'Server error while updating profile',
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
};

/**
 * @desc    Update profile image
 * @route   PUT /api/user/profile-image
 * @access  Private
 */
const updateProfileImage = async (req, res) => {
  try {
    const { profileImage } = req.body;

    if (!profileImage) {
      return res.status(400).json({
        success: false,
        message: 'Profile image URL is required',
      });
    }

    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    user.profileImage = profileImage;
    await user.save({ validateBeforeSave: false });

    console.log(`✅ Profile image updated: ${user.email}`);

    res.status(200).json({
      success: true,
      message: 'Profile image updated successfully',
      profileImage: user.profileImage,
    });

  } catch (error) {
    console.error('❌ Update profile image error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while updating profile image',
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
};

/**
 * @desc    Delete user account
 * @route   DELETE /api/user/account
 * @access  Private
 */
const deleteAccount = async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({
        success: false,
        message: 'Password is required to delete account',
      });
    }

    const user = await User.findById(req.user._id).select('+password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Verify password
    const isPasswordCorrect = await user.comparePassword(password);

    if (!isPasswordCorrect) {
      return res.status(401).json({
        success: false,
        message: 'Incorrect password',
      });
    }

    // Soft delete (deactivate) instead of hard delete
    user.isActive = false;
    user.email = `deleted_${Date.now()}_${user.email}`;
    user.username = `deleted_${Date.now()}_${user.username}`;
    await user.save({ validateBeforeSave: false });

    console.log(`🗑️ Account deleted: ${req.user.email} (ID: ${req.user._id})`);

    res.status(200).json({
      success: true,
      message: 'Account deleted successfully',
    });

  } catch (error) {
    console.error('❌ Delete account error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while deleting account',
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
};

/**
 * @desc    Get user stats (example additional endpoint)
 * @route   GET /api/user/stats
 * @access  Private
 */
const getUserStats = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const stats = {
      accountCreated: user.createdAt,
      lastLogin: user.lastLogin,
      isEmailVerified: user.isEmailVerified,
      accountAge: Math.floor((Date.now() - user.createdAt) / (1000 * 60 * 60 * 24)), // days
    };

    res.status(200).json({
      success: true,
      stats,
    });

  } catch (error) {
    console.error('❌ Get stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
};

module.exports = {
  getProfile,
  updateProfile,
  updateProfileImage,
  deleteAccount,
  getUserStats,
};