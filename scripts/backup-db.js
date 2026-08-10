// Резервное копирование базы данных.
// Запуск вручную:  node scripts/backup-db.js
// Автоматически (пример cron, каждый день в 3:00 ночи):
//   0 3 * * * cd /path/to/edu-portal && node scripts/backup-db.js >> backups/backup.log 2>&1
//
// Использует встроенный механизм .backup() better-sqlite3 — делает целостный
// снимок базы даже во время работы сервера (WAL-safe), не останавливая приложение.

const path     = require('path');
const fs       = require('fs');
const Database = require('better-sqlite3');

const DATA_DIR    = process.env.DATA_DIR || path.join(__dirname, '..');
const DB_PATH     = path.join(DATA_DIR, 'database.db');
const BACKUP_DIR  = path.join(DATA_DIR, 'backups');
const KEEP_LAST_N = parseInt(process.env.BACKUP_KEEP || '14', 10); // сколько последних копий хранить

async function main() {
  if (!fs.existsSync(DB_PATH)) {
    console.error(`❌ Файл базы данных не найден: ${DB_PATH}`);
    process.exit(1);
  }
  if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

  const stamp      = new Date().toISOString().replace(/[:.]/g, '-');
  const backupPath = path.join(BACKUP_DIR, `database-${stamp}.db`);

  const db = new Database(DB_PATH, { readonly: true });
  try {
    await db.backup(backupPath);
    console.log(`✅ Бэкап создан: ${backupPath}`);
  } finally {
    db.close();
  }

  rotateOldBackups();
}

function rotateOldBackups() {
  const files = fs.readdirSync(BACKUP_DIR)
    .filter(f => f.startsWith('database-') && f.endsWith('.db'))
    .map(f => ({ name: f, time: fs.statSync(path.join(BACKUP_DIR, f)).mtimeMs }))
    .sort((a, b) => b.time - a.time);

  const toDelete = files.slice(KEEP_LAST_N);
  toDelete.forEach(f => {
    fs.unlinkSync(path.join(BACKUP_DIR, f.name));
    console.log(`🗑  Удалён старый бэкап: ${f.name}`);
  });

  console.log(`ℹ️  Хранится бэкапов: ${Math.min(files.length, KEEP_LAST_N)} (лимит ${KEEP_LAST_N})`);
}

main().catch(e => {
  console.error('❌ Ошибка резервного копирования:', e.message);
  process.exit(1);
});
