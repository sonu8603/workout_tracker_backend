const jwt = require("jsonwebtoken");
const User = require("../models/User");

/**
 * Production-Ready Authentication Middleware
 * Protects routes by validating JWT tokens and checking user status
 */
const protect = async (req, res, next) => {
  try {
    // 1. Extract token from Authorization header
    const authHeader = req.header("Authorization");

    if (!authHeader) {
      return res.status(401).json({ 
        success: false,
        message: "Access denied. No token provided.",
        code: "NO_TOKEN"
      });
    }

    // 2. Parse Bearer token
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : authHeader.trim();

    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: "Unauthorized access.",
        code: "INVALID_FORMAT"
      });
    }

    // 3. Verify JWT_SECRET exists
    if (!process.env.JWT_SECRET) {
      console.error(" CRITICAL: JWT_SECRET is not defined in environment variables");
      return res.status(500).json({ 
        success: false,
        message: "Server configuration error" 
      });
    }

    // 4. Verify and decode token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 5. Check if user still exists and is active
    const user = await User.findById(decoded.id).select('-password');

    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: "User no longer exists. Please login again.",
        code: "USER_NOT_FOUND"
      });
    }

    if (!user.isActive) {
      return res.status(401).json({ 
        success: false,
        message: "Account is deactivated. Please contact support.",
        code: "ACCOUNT_DEACTIVATED"
      });
    }

    // 6. Check if user changed password after token was issued
    if (user.passwordChangedAt) {
      const changedTimestamp = parseInt(user.passwordChangedAt.getTime() / 1000, 10);
      if (decoded.iat < changedTimestamp) {
        return res.status(401).json({ 
          success: false,
          message: "Password was recently changed. Please login again.",
          code: "PASSWORD_CHANGED"
        });
      }
    }

    // 7. Attach user to request
    req.user = user;
    req.userId = user._id;
    req.token = token;

    // 8. Token expiration warning (optional logging)
    if (decoded.exp) {
      const expiresIn = decoded.exp - Math.floor(Date.now() / 1000);
      if (expiresIn < 300 && process.env.NODE_ENV === 'development') {
        console.warn(` Token expiring soon (${Math.floor(expiresIn / 60)}min) for user: ${user.email}`);
      }
    }

    next();

  } catch (error) {
    // Handle specific JWT errors
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ 
        success: false,
        message: "session has expired. Please login again.",
        code: "TOKEN_EXPIRED"
      });
    }

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ 
        success: false,
        message: "Invalid token. Authentication failed.",
        code: "INVALID_TOKEN"
      });
    }

    if (error.name === "NotBeforeError") {
      return res.status(401).json({ 
        success: false,
        message: "session not active yet. please try again later",
        code: "TOKEN_NOT_ACTIVE"
      });
    }

    // Log unexpected errors
    console.error(" Auth Middleware Error:", error);

    return res.status(500).json({ 
      success: false,
      message: "Authentication error. Please try again.",
      code: "AUTH_ERROR"
    });
  }
};

/**
 * Role-based authorization middleware
 * Usage: router.get('/admin', protect, authorize('admin'), controller)
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        success: false,
        message: "Authentication required",
        code: "NOT_AUTHENTICATED"
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        success: false,
        message: `Access forbidden. This route requires one of these roles: ${roles.join(', ')}`,
        code: "FORBIDDEN",
        requiredRoles: roles,
        userRole: req.user.role
      });
    }

    next();
  };
};

/**
 * Optional authentication middleware
 * Attaches user if token exists, but doesn't block request
 * Useful for routes that have different behavior for authenticated vs unauthenticated users
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.header("Authorization");
    
    if (authHeader) {
      const token = authHeader.startsWith("Bearer ")
        ? authHeader.slice(7).trim()
        : authHeader.trim();

      if (token && process.env.JWT_SECRET) {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        
        if (user && user.isActive) {
          req.user = user;
          req.userId = user._id;
        }
      }
    }
  } catch (error) {
    // Silently fail for optional auth
    req.user = null;
  }

  next();
};

/**
 * Refresh token middleware (if implementing token refresh)
 * Generates new token if current one is about to expire
 */
const refreshIfNeeded = async (req, res, next) => {
  try {
    if (!req.token) {
      return next();
    }

    const decoded = jwt.verify(req.token, process.env.JWT_SECRET);
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = decoded.exp - now;
    
    //  Refresh if token expires in less than 2 days (172800 seconds)
    const refreshThreshold = 2 * 24 * 60 * 60;
    
    if (expiresIn < refreshThreshold && expiresIn > 0 && req.user) {
      const newToken = jwt.sign(
        { 
          id: req.user._id,
          iat: now
        },
        process.env.JWT_SECRET,
        { 
          expiresIn: process.env.JWT_EXPIRE || '7d',
          algorithm: 'HS256'
        }
      );
      
      // Set both header variations for compatibility
      res.setHeader('X-New-Token', newToken);
      res.setHeader('x-new-token', newToken);
      
      if (process.env.NODE_ENV === 'development') {
        console.log(`🔄 Token refreshed for user: ${req.user.email}`);
        console.log(`   Old token expires in: ${Math.floor(expiresIn / 3600)}h`);
        console.log(`   New token valid for: ${process.env.JWT_EXPIRE || '7d'}`);
      }
    }
  } catch (error) {
    if (process.env.NODE_ENV === 'development') {
      console.warn('⚠️ Token refresh failed:', error.message);
    }
  }
  
  next();
};

module.exports = { 
  protect, 
  authorize, 
  optionalAuth,
  refreshIfNeeded,
};