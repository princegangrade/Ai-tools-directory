// server/middleware/auth.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET; // Ensure JWT_SECRET is loaded via server.js preloading dotenv

const authenticateToken = (req, res, next) => {
    // Get token from the Authorization header (e.g., "Bearer TOKEN_STRING")
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract token after "Bearer "

    if (token == null) {
        console.log('Auth Middleware: No token provided.');
        // No token provided
        return res.status(401).json({ error: 'Unauthorized: Access token is required.' });
    }

    // Verify the token
    jwt.verify(token, JWT_SECRET, (err, decodedPayload) => {
        if (err) {
            console.log('Auth Middleware: Token verification failed.', err.message);
             // Token is invalid (expired, wrong secret, etc.)
             if (err.name === 'TokenExpiredError') {
                 return res.status(401).json({ error: 'Unauthorized: Token has expired.' });
             }
            return res.status(403).json({ error: 'Forbidden: Invalid token.' }); // Use 403 for invalid token
        }

        // Token is valid, attach decoded payload (user info) to the request object
        // We stored { userId: ..., email: ... } in the payload during login
        req.user = decodedPayload;
        console.log('Auth Middleware: Token verified for user ID:', req.user.userId);

        // Proceed to the next middleware or the route handler
        next();
    });
};

module.exports = authenticateToken; // Export the middleware function
