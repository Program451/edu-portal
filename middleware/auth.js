'use strict';
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config');

// ─────────────────────────────────────────────
// MIDDLEWARE АВТОРИЗАЦИИ
// ─────────────────────────────────────────────
function requireAuth(...roles) {
  return (req, res, next) => {
    const header = req.headers['authorization'] || '';
    const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Токен не найден' });
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      if (roles.length && !roles.includes(payload.role)) {
        return res.status(403).json({ error: 'Недостаточно прав' });
      }
      req.user = payload;
      next();
    } catch {
      return res.status(401).json({ error: 'Токен недействителен' });
    }
  };
}

module.exports = { requireAuth };
