const User = require('../models/user');
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


    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: sanitizeUser(user),
    });

  } catch (error) {
    console.error(' Register error:', error);
    
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
    // Validate input
    if (!identifier || !password) {
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

    console.log(' User found:', user ? `${user.email} (${user.username})` : 'NO USER FOUND');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'invalid credentials',
      });
    }

    //  Check if account is locked BEFORE password check
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 1000); // seconds
      const remainingMinutes = Math.ceil(remainingTime / 60);
      
      return res.status(423).json({ // 423 = Locked
        success: false,
        message: `Account is locked. Please try again in ${remainingMinutes} minute${remainingMinutes > 1 ? 's' : ''}.`,
        code: 'ACCOUNT_LOCKED',
        lockUntil: user.lockUntil,
        remainingSeconds: remainingTime,
        remainingMinutes: remainingMinutes
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

    // Check password
    const isPasswordCorrect = await user.comparePassword(password);
    if (!isPasswordCorrect) {
      // Increment login attempts
      await user.incLoginAttempts();
      
      // Reload user to get updated lock status
      const updatedUser = await User.findById(user._id);
      
      // Check if account just got locked
      if (updatedUser.lockUntil && updatedUser.lockUntil > Date.now()) {
        const remainingTime = Math.ceil((updatedUser.lockUntil - Date.now()) / 1000);
        const remainingMinutes = Math.ceil(remainingTime / 60);
        
        return res.status(423).json({
          success: false,
          message: `Too many failed attempts. Account locked for ${remainingMinutes} minute${remainingMinutes > 1 ? 's' : ''}.`,
          code: 'ACCOUNT_LOCKED',
          lockUntil: updatedUser.lockUntil,
          remainingSeconds: remainingTime,
          remainingMinutes: remainingMinutes
        });
      }
      
      // Show remaining attempts
      const maxAttempts = 5;
      const attemptsLeft = maxAttempts - updatedUser.loginAttempts;
      
      return res.status(401).json({
        success: false,
        message: attemptsLeft > 0 
          ? `Invalid credentials. ${attemptsLeft} attempt${attemptsLeft > 1 ? 's' : ''} remaining.`
          : 'Invalid credentials',
        attemptsLeft: attemptsLeft > 0 ? attemptsLeft : 0
      });
    }

    // Reset login attempts on successful login
    if (user.loginAttempts > 0 || user.lockUntil) {
      await user.resetLoginAttempts();
    }

    // Update last login
    user.lastLogin = Date.now();
    await user.save({ validateBeforeSave: false });

    // Generate token
    const token = generateToken(user._id);

    // Login  success
    res.status(200).json({
      success: true,
      message: 'Login successful',
      token,
      user: sanitizeUser(user),
    });

  } catch (error) {
    console.error(' Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login',
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
};

/**
 * @desc    Forgot password - Send OTP
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
        message: 'If an account with that email exists, an OTP has been sent.',
      });
    }

    // Check if user is active
    if (!user.isActive) {
      return res.status(200).json({
        success: true,
        message: 'If an account with that email exists, an OTP has been sent.',
      });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Hash OTP before storing (security best practice)
    const hashedOTP = crypto
      .createHash('sha256')
      .update(otp)
      .digest('hex');

    // Store hashed OTP and expiry (10 minutes)
    user.resetPasswordToken = hashedOTP;
    user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save({ validateBeforeSave: false });

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
            text-align: center;
          }
          .otp-box {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            font-size: 42px;
            font-weight: bold;
            letter-spacing: 8px;
            padding: 25px;
            margin: 30px auto;
            border-radius: 10px;
            display: inline-block;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
          }
          .warning {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
            text-align: left;
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
            <h1>🔒 Password Reset OTP</h1>
          </div>
          <div class="content">
            <p>Hi <strong>${user.username}</strong>,</p>
            <p>You requested to reset your password. Use the OTP below:</p>
            
            <div class="otp-box">
              ${otp}
            </div>
            
            <div class="warning">
              <strong>⚠️ Important:</strong>
              <ul style="margin: 10px 0;">
                <li>This OTP will <span class="expiry">expire in 10 minutes</span></li>
                <li>Never share this OTP with anyone</li>
                <li>If you didn't request this, please ignore this email</li>
              </ul>
            </div>
            
            <p style="color: #666; font-size: 14px; margin-top: 30px;">
              Enter this OTP in the app to reset your password.
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
        subject: 'Password Reset OTP -  Fitmatrics',
        html,
      });

     if (!emailSent.success) {
    throw new Error('Email sending failed');
}


      console.log(` OTP sent to: ${email}`);

      res.status(200).json({
        success: true,
        message: 'OTP sent to your email successfully',
      });

    } catch (emailError) {
      // Clear reset token if email fails
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save({ validateBeforeSave: false });
    
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


/**
 * @desc    Verify OTP (separate endpoint for validation)
 * @route   POST /api/auth/verify-otp
 * @access  Public
 */
const verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    // Validate input
    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: 'Please provide email and OTP',
      });
    }

    // Hash the OTP to compare with DB
    const hashedOTP = crypto
      .createHash('sha256')
      .update(otp.toString().trim())
      .digest('hex');

    // Find user with valid OTP and not expired
    const user = await User.findOne({
      email: email.trim().toLowerCase(),
      resetPasswordToken: hashedOTP,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired OTP',
        code: 'INVALID_OTP'
      });
    }

    res.status(200).json({
      success: true,
      message: 'OTP verified successfully',
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.',
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
};

/**
 * @desc     reset password
 * @route   POST /api/auth/reset-password
 * @access  Public
 */
const resetPassword = async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Please provide email and new password',
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters',
      });
    }

    const user = await User.findOne({
      email: email.trim().toLowerCase(),
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Set new password
    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    user.passwordChangedAt = Date.now();
    await user.save();
    
    res.status(200).json({
      success: true,
      message: 'Password reset successfully. You can now login with your new password.',
    });

  } catch (error) {
    console.error(' Reset password error:', error);
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
    console.error('❌ Logout error:', error);
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
   verifyOTP,
  resetPassword,
  logout,
  getMe,
};