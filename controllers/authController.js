const User = require('../models/User');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const sendEmail = require('../utils/sendEmail');
const { validationResult } = require('express-validator');

// Generate JWT Token with enhanced security
const generateToken = (userId) => {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not defined in environment variables');
  }

  return jwt.sign(
    { 
      id: userId,
      iat: Math.floor(Date.now() / 1000)
    },
    process.env.JWT_SECRET,
    { 
      expiresIn: process.env.JWT_EXPIRE || '7d',
      algorithm: 'HS256'
    }
  );
};

// Sanitize user data for response
const sanitizeUser = (user) => ({
  id: user._id,
  username: user.username,
  email: user.email,
  phone: user.phone,
  profileImage: user.profileImage,
  role: user.role,
  isActive: user.isActive,
  createdAt: user.createdAt
});

/**
 * @desc    Register new user
 * @route   POST /api/auth/register
 * @access  Public
 */
const register = async (req, res) => {
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

    let { username, email, password, phone } = req.body;

    // Sanitize inputs
    email = email.trim().toLowerCase();
    username = username.trim();
    phone = phone ? phone.trim() : '';

    // Check for existing user
    const userExists = await User.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (userExists) {
      const field = userExists.email === email ? 'Email' : 'Username';
      return res.status(400).json({
        success: false,
        message: `${field} already registered`,
        field: field.toLowerCase()
      });
    }

    // Validate password strength
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters',
        field: 'password'
      });
    }

    // Create user
    const user = await User.create({
      username,
      email,
      password,
      phone,
    });

    // Generate token
    const token = generateToken(user._id);

    // Log success (without sensitive data)
    console.log(`✅ User registered: ${email} (ID: ${user._id})`);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: sanitizeUser(user),
    });

  } catch (error) {
    console.error('❌ Register error:', error);
    
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
      message: 'Server error during registration',
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
};

/**
 * @desc    Login user
 * @route   POST /api/auth/login
 * @access  Public
 */
const login = async (req, res) => {
  try {
    const { identifier, password } = req.body;

    console.log('🔍 Login attempt:', { identifier, hasPassword: !!password });

    // Validate input
    if (!identifier || !password) {
      console.log('❌ Missing credentials');
      return res.status(400).json({
        success: false,
        message: 'Please provide username/email and password',
      });
    }

    const trimmedIdentifier = identifier.trim();

    // Find user (by email or username)
    const user = await User.findOne({
      $or: [
        { email: trimmedIdentifier.toLowerCase() }, 
        { username: trimmedIdentifier }
      ]
    }).select('+password');

    console.log('🔍 User found:', user ? `${user.email} (${user.username})` : 'NO USER FOUND');

    if (!user) {
      console.log('❌ No user found with identifier:', trimmedIdentifier);
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    // Check password
    const isPasswordCorrect = await user.comparePassword(password);
    console.log('🔍 Password correct:', isPasswordCorrect);

    if (!isPasswordCorrect) {
      console.log('❌ Password incorrect for user:', user.email);
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    // Check if account is active
    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Account is deactivated. Please contact support.',
        code: 'ACCOUNT_DEACTIVATED'
      });
    }

    // Update last login
    user.lastLogin = Date.now();
    await user.save({ validateBeforeSave: false });

    // Generate token
    const token = generateToken(user._id);

    // Log success
    console.log(`✅ User logged in: ${user.email} (ID: ${user._id})`);

    res.status(200).json({
      success: true,
      message: 'Login successful',
      token,
      user: sanitizeUser(user),
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login',
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
};

/**
 * @desc    Forgot password - Send reset email
 * @route   POST /api/auth/forgot-password
 * @access  Public
 */
const forgotPassword = async (req, res) => {
  try {
    let { email } = req.body;

    // Validate email
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an email address',
      });
    }

    email = email.trim().toLowerCase();

    // Find user
    const user = await User.findOne({ email });

    if (!user) {
      // Don't reveal if user exists (security best practice)
      return res.status(200).json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent.',
      });
    }

    // Check if user is active
    if (!user.isActive) {
      return res.status(200).json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent.',
      });
    }

    // Generate reset token
    const resetToken = user.getResetPasswordToken();
    await user.save({ validateBeforeSave: false });

    // Create reset URL
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    // Email HTML template
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6; 
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
          }
          .container { 
            max-width: 600px; 
            margin: 20px auto; 
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
          }
          .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 40px 30px; 
            text-align: center; 
          }
          .header h1 {
            margin: 0;
            font-size: 28px;
          }
          .content { 
            padding: 40px 30px; 
          }
          .button { 
            display: inline-block; 
            background: #667eea; 
            color: white !important; 
            padding: 14px 35px; 
            text-decoration: none; 
            border-radius: 6px; 
            margin: 20px 0;
            font-weight: 600;
            transition: background 0.3s;
          }
          .button:hover {
            background: #5568d3;
          }
          .warning {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
          }
          .footer { 
            text-align: center; 
            padding: 20px;
            background: #f9f9f9;
            color: #999; 
            font-size: 13px;
            border-top: 1px solid #eee;
          }
          .expiry {
            color: #dc3545;
            font-weight: 600;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔒 Password Reset Request</h1>
          </div>
          <div class="content">
            <p>Hi <strong>${user.username}</strong>,</p>
            <p>You requested to reset your password. Click the button below to create a new password:</p>
            <div style="text-align: center;">
              <a href="${resetUrl}" class="button">Reset Password</a>
            </div>
            <div class="warning">
              <strong>⚠️ Important:</strong>
              <ul style="margin: 10px 0;">
                <li>This link will <span class="expiry">expire in 10 minutes</span></li>
                <li>For security, never share this link with anyone</li>
                <li>If you didn't request this, please ignore this email</li>
              </ul>
            </div>
            <p style="color: #666; font-size: 14px;">
              If the button doesn't work, copy and paste this link into your browser:<br>
              <code style="background: #f4f4f4; padding: 8px; display: inline-block; margin-top: 10px; border-radius: 4px; word-break: break-all;">${resetUrl}</code>
            </p>
          </div>
          <div class="footer">
            <p><strong>Workout Tracker App</strong> © ${new Date().getFullYear()}</p>
            <p>This is an automated email. Please do not reply.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    // Send email
    try {
      const emailSent = await sendEmail({
        email: user.email,
        subject: 'Password Reset Request - Workout Tracker',
        html,
      });

      if (!emailSent) {
        throw new Error('Email sending failed');
      }

      console.log(`📧 Password reset email sent to: ${email}`);

      res.status(200).json({
        success: true,
        message: 'Password reset email sent successfully',
      });

    } catch (emailError) {
      // Clear reset token if email fails
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save({ validateBeforeSave: false });

      console.error(' Email sending error:', emailError);

      return res.status(500).json({
        success: false,
        message: 'Email could not be sent. Please try again later.',
      });
    }

  } catch (error) {
    console.error(' Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.',
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
};


const resetPassword = async (req, res) => {
  try {
    const { newPassword } = req.body;
    const { resetToken } = req.params;

    // Validate input
    if (!newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a new password',
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters',
      });
    }

    // Hash the token to compare with DB
    const hashedToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');

    // Find user with valid token and not expired
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset token. Please request a new password reset.',
        code: 'INVALID_TOKEN'
      });
    }

    // Set new password (will be hashed by pre-save hook)
    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    user.passwordChangedAt = Date.now();
    await user.save();

    console.log(`✅ Password reset successful for: ${user.email}`);

    res.status(200).json({
      success: true,
      message: 'Password reset successfully. You can now login with your new password.',
    });

  } catch (error) {
    console.error('❌ Reset password error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.',
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
};

const logout = async (req, res) => {
  try {
    // Optional: Log the logout event
    if (req.user) {
      console.log(`🚪 User logged out: ${req.user.email} (ID: ${req.user._id})`);
    }

    // Note: With JWT, actual logout happens client-side by deleting the token
    // This endpoint is mainly for logging/analytics
    // For token blacklisting, you'd add the token to a blacklist here

    res.status(200).json({
      success: true,
      message: 'Logged out successfully',
    });

  } catch (error) {
    console.error(' Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during logout',
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
};



const getMe = async (req, res) => {
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
      user: sanitizeUser(user),
    });

  } catch (error) {
   
    res.status(500).json({
      success: false,
      message: 'Server error',
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
};

module.exports = {
  register,
  login,
  forgotPassword,
  resetPassword,
  logout,
  getMe,
};