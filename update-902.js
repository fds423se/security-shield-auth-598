const jwt = require('jsonwebtoken');

const SECRET_KEY = process.env.SHIELD_AUTH_SECRET || 'shield-default-598-key';

/**
 * Validates the security shield authorization token from request headers.
 */
const authenticateShieldToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      status: 'error', 
      message: 'Authentication token missing.' 
    });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ 
      status: 'error', 
      message: 'Invalid or expired authentication token.' 
    });
  }
};

module.exports = { authenticateShieldToken };