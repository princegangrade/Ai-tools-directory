// server/middleware/auth.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET; // Ensure JWT_SECRET is loaded via server.js preloading dotenv

const authenticateToken = (req, res, next) => {
    // Get token from the Authorization header (e.g., "Bearer TOKEN_STRING")
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract token after "Bearer "

    if (token == null) {
        // console.log('Auth: No token provided.'); // Less verbose logging
        // No token provided
        return res.status(401).json({ error: 'Unauthorized: Access token is required.' });
    }

    // Verify the token
    jwt.verify(token, JWT_SECRET, (err, decodedPayload) => {
        if (err) {
            // console.log('Auth: Token verification failed.', err.message); // Less verbose logging
             // Token is invalid (expired, wrong secret, etc.)
             if (err.name === 'TokenExpiredError') {
                 return res.status(401).json({ error: 'Unauthorized: Token has expired.' });
             }
            return res.status(403).json({ error: 'Forbidden: Invalid token.' }); // Use 403 for invalid token
        }

        // Token is valid, attach decoded payload (user info) to the request object
        req.user = decodedPayload;
        // console.log('Auth: Token verified for user ID:', req.user.userId); // Less verbose logging

        // Proceed to the next middleware or the route handler
        next();
    });
};

module.exports = authenticateToken; // Export the middleware function
