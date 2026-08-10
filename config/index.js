'use strict';
// ─────────────────────────────────────────────
// КОНФИГУРАЦИЯ
// Все настройки, читаемые из переменных окружения (.env), в одном месте.
// Раньше были разбросаны по всему server.js — теперь один источник правды,
// который можно require() из любого модуля.
// ─────────────────────────────────────────────
require('dotenv').config();
const path = require('path');
const fs   = require('fs');
const crypto = require('crypto');

const PORT     = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..');
const UPLOADS  = path.join(DATA_DIR, 'uploads');
const DB_PATH  = path.join(DATA_DIR, 'database.db');

// JWT_SECRET больше не хранится в коде как дефолт.
// Если переменная окружения не задана — раньше секрет генерировался заново
// при каждом запуске процесса, и все выданные токены "слетали" при любом
// перезапуске сервера (а на бесплатном/временном хостинге сервер может
// перезапускаться сам по себе — например, при "засыпании" от простоя).
// Теперь в этом случае секрет генерируется один раз и сохраняется в файл
// рядом с базой данных (.jwt-secret) — при следующих запусках он читается
// оттуда, и пользователи не будут разлогиниваться "на ровном месте".
// Как только вы зададите JWT_SECRET в .env / Environment Variables — он
// станет использоваться вместо файла, а .jwt-secret можно удалить.
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  const secretFile = path.join(DATA_DIR, '.jwt-secret');
  try {
    JWT_SECRET = fs.readFileSync(secretFile, 'utf8').trim();
  } catch (e) {
    JWT_SECRET = crypto.randomBytes(48).toString('hex');
    try {
      fs.writeFileSync(secretFile, JWT_SECRET, { mode: 0o600 });
    } catch (writeErr) {
      console.warn('⚠️  Не удалось сохранить .jwt-secret на диск:', writeErr.message);
    }
  }
  console.warn('⚠️  JWT_SECRET не задан в переменных окружения!');
  console.warn('⚠️  Используется секрет из файла .jwt-secret (создан автоматически) — токены переживут перезапуск сервера.');
  console.warn('⚠️  Для продакшена всё равно лучше задать свой JWT_SECRET в .env / Environment Variables и не хранить секрет в файле рядом с кодом.');
}

// Создаём папку uploads если её нет
if (!fs.existsSync(UPLOADS)) fs.mkdirSync(UPLOADS, { recursive: true });

const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
if (!GROQ_API_KEY) {
  console.warn('⚠️  GROQ_API_KEY не задан в переменных окружения — AI-помощница Айгуль работать не будет.');
}

const ADMIN_DEFAULT_PASSWORD = process.env.ADMIN_DEFAULT_PASSWORD || '';

module.exports = {
  PORT,
  DATA_DIR,
  UPLOADS,
  DB_PATH,
  JWT_SECRET,
  GROQ_API_KEY,
  ADMIN_DEFAULT_PASSWORD
};
