const jwt = require('jsonwebtoken');

const { generateError } = require('../controllers/errorController');
const { checkInternal } = require("../utils/security")

const dotenv = require('dotenv');
dotenv.config();

const secret = process.env.secret

function verifyToken(token) {
    try {
        const decoded = jwt.verify(token, secret);
        return decoded.role;
    } catch (error) {
        return null
    }
}

const authMiddleware = (requiredRole) => {
    return (req, res, next) => {
        const token = req.query.token;

        if (!token) {
            return next(generateError(401, "Access denied. Token is required."));
        }

        const role = verifyToken(token);

        if (!role) {
            return next(generateError(401, "Invalid or expired token."));
        }

        if (requiredRole === "admin" && role !== "admin") {
            return next(generateError(401, "Unauthorized."));
        } else if (requiredRole === "admin" && role === "admin") {
            if (!checkInternal(req)) {
                return next(generateError(403, "Only available for internal users!"));
            }
        }

        next();
    };
};

function generateGuestToken(req, res, next) {
    const payload = {
        role: 'user'
    };

    jwt.sign(payload, secret, (err, token) => {
        if (err) {
            next(generateError(500, "Failed to generate token."));;
        } else {
            res.send(token);
        }
    });
}

module.exports = {authMiddleware, generateGuestToken}