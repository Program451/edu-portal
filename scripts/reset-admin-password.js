'use strict';
// Принудительно сбрасывает пароль пользователя admin на заданный.
// Нужен, если пароль, показанный при первом запуске сервера, был утерян
// (не скопирован вовремя, скопирован с лишними пробелами/переносом строки,
// или сервер перезапускался несколько раз до того, как пароль сохранили).
//
// Запуск (из папки проекта, рядом с server.js):
//   node scripts/reset-admin-password.js НовыйПароль123
//
// Если аргумент не указать — будет сгенерирован случайный пароль и выведен
// на экран (как при первом запуске).

const path = require('path');
const bcrypt = require('bcrypt');
const { db } = require('../db');

const newPassword = process.argv[2] || require('crypto').randomBytes(9).toString('base64url');

const admin = db.prepare("SELECT id, username FROM users WHERE role = 'admin' ORDER BY id ASC LIMIT 1").get();

if (!admin) {
  console.error('❌ В базе не найден ни один пользователь с ролью admin. Запустите сервер (npm start) один раз — он создаст админа автоматически.');
  process.exit(1);
}

const hash = bcrypt.hashSync(newPassword, 12);
db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, admin.id);

console.log('✅ Пароль обновлён.');
console.log(`   Логин:  ${admin.username}`);
console.log(`   Пароль: ${newPassword}`);
console.log('   ⚠️  Скопируйте пароль сейчас. При входе вставляйте его без пробелов до/после.');
