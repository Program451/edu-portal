'use strict';
const Database = require('better-sqlite3');
const bcrypt   = require('bcrypt');
const { DB_PATH, ADMIN_DEFAULT_PASSWORD } = require('../config');

// ─────────────────────────────────────────────
// БАЗА ДАННЫХ
// ─────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name     TEXT,
    role          TEXT NOT NULL CHECK(role IN ('admin','teacher','student')),
    created_at    TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS playlists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    description TEXT,
    teacher_id  INTEGER NOT NULL,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS lessons (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    playlist_id     INTEGER NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    video_2d_path   TEXT,
    video_vr_path   TEXT,
    material_path   TEXT,
    order_index     INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(playlist_id) REFERENCES playlists(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS homework_submissions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    lesson_id    INTEGER NOT NULL,
    student_id   INTEGER NOT NULL,
    file_path    TEXT NOT NULL,
    submitted_at TEXT DEFAULT CURRENT_TIMESTAMP,
    grade        INTEGER,
    comment      TEXT,
    graded_at    TEXT,
    FOREIGN KEY(lesson_id)  REFERENCES lessons(id) ON DELETE CASCADE,
    FOREIGN KEY(student_id) REFERENCES users(id)   ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS grades (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    teacher_id INTEGER,
    lesson_id  INTEGER,
    value      INTEGER NOT NULL,
    comment    TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY(lesson_id)  REFERENCES lessons(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS quizzes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title      TEXT NOT NULL,
    teacher_id INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS quiz_questions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    quiz_id             INTEGER NOT NULL,
    question_text       TEXT,
    question_image_path TEXT,
    multiple_correct    INTEGER DEFAULT 0,
    order_index         INTEGER DEFAULT 0,
    FOREIGN KEY(quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS quiz_options (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id       INTEGER NOT NULL,
    option_text       TEXT,
    option_image_path TEXT,
    is_correct        INTEGER DEFAULT 0,
    FOREIGN KEY(question_id) REFERENCES quiz_questions(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS quiz_results (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    quiz_id      INTEGER NOT NULL,
    student_id   INTEGER NOT NULL,
    score        INTEGER NOT NULL,
    total        INTEGER NOT NULL,
    completed_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(quiz_id)    REFERENCES quizzes(id) ON DELETE CASCADE,
    FOREIGN KEY(student_id) REFERENCES users(id)   ON DELETE CASCADE
  );

  -- Библиотека: книги, которые загружают учителя/операторы, и подборки (плейлисты) из этих книг
  CREATE TABLE IF NOT EXISTS library_books (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    author      TEXT,
    description TEXT,
    category    TEXT,
    file_path   TEXT NOT NULL,
    file_name   TEXT,
    cover_path  TEXT,
    uploaded_by INTEGER NOT NULL,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS library_playlists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    description TEXT,
    owner_id    INTEGER NOT NULL,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS library_playlist_items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    playlist_id INTEGER NOT NULL,
    book_id     INTEGER NOT NULL,
    order_index INTEGER DEFAULT 0,
    added_at    TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(playlist_id) REFERENCES library_playlists(id) ON DELETE CASCADE,
    FOREIGN KEY(book_id)     REFERENCES library_books(id)     ON DELETE CASCADE,
    UNIQUE(playlist_id, book_id)
  );
`);

// ─────────────────────────────────────────────
// МИГРАЦИЯ: роль 'operator' (SQLite не даёт менять CHECK на лету)
// ─────────────────────────────────────────────
(function migrateUsersRole() {
  const row = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").get();
  if (row && !row.sql.includes('operator')) {
    // ВАЖНО: PRAGMA legacy_alter_table = ON нужен, чтобы SQLite НЕ переписывал
    // "REFERENCES users(id)" на "REFERENCES users_old(id)" во всех таблицах,
    // у которых есть внешний ключ на users (playlists, grades, quizzes и т.д.).
    // Без этой прагмы (при foreign_keys = ON) SQLite при RENAME TABLE
    // автоматически подменяет имя таблицы во всех внешних ключах,
    // ссылающихся на неё — а после DROP TABLE users_old эти ссылки становятся
    // "битыми" (таблицы users_old больше не существует), и любой INSERT в
    // playlists/grades/quizzes/homework_submissions/quiz_results падает
    // с ошибкой "no such table: main.users_old".
    db.pragma('legacy_alter_table = ON');
    db.exec(`
      ALTER TABLE users RENAME TO users_old;
      CREATE TABLE users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name     TEXT,
        role          TEXT NOT NULL CHECK(role IN ('admin','operator','teacher','student')),
        created_at    TEXT DEFAULT CURRENT_TIMESTAMP
      );
      INSERT INTO users (id, username, password_hash, full_name, role, created_at)
        SELECT id, username, password_hash, full_name, role, created_at FROM users_old;
      DROP TABLE users_old;
    `);
    db.pragma('legacy_alter_table = OFF');
    console.log('✅ Миграция: роль operator добавлена в таблицу users');
  }
})();

// ─────────────────────────────────────────────
// МИГРАЦИЯ: teacher_id в grades делаем nullable + ON DELETE SET NULL
// (раньше было NOT NULL + ON DELETE CASCADE — при удалении учителя
// бесследно пропадали ВСЕ оценки, которые он когда-либо поставил студентам.
// Оценка — это академическая запись студента и должна сохраняться
// независимо от того, удалён ли впоследствии аккаунт того, кто её поставил.)
// ─────────────────────────────────────────────
(function migrateGradesTeacherNullable() {
  const row = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='grades'").get();
  if (!row) return;
  const needsMigration = /teacher_id\s+INTEGER\s+NOT\s+NULL/i.test(row.sql)
    || /FOREIGN KEY\(teacher_id\)\s*REFERENCES\s*users\(id\)\s*ON DELETE CASCADE/i.test(row.sql);
  if (!needsMigration) return;

  console.warn('⚠️  Обнаружена устаревшая схема grades (teacher_id NOT NULL + CASCADE) — мигрируем...');
  db.pragma('legacy_alter_table = ON');
  db.pragma('foreign_keys = OFF');

  const migrate = db.transaction(() => {
    // Берём РЕАЛЬНУЮ текущую схему таблицы (со всеми колонками, добавленными
    // через addColumnIfMissing за время жизни базы: group_id, playlist_id,
    // control_type, max_value, graded_by, edited_by, edited_at, original_value
    // и т.д.) и точечно меняем только определение teacher_id — ничего другого
    // не трогаем, чтобы не потерять данные в остальных колонках.
    const fixedSql = row.sql
      .replace(/teacher_id\s+INTEGER\s+NOT\s+NULL/i, 'teacher_id INTEGER')
      .replace(/FOREIGN KEY\(teacher_id\)\s*REFERENCES\s*users\(id\)\s*ON DELETE CASCADE/i,
               'FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE SET NULL');

    const cols = db.prepare(`PRAGMA table_info(grades)`).all().map(c => c.name).join(', ');
    db.exec(`ALTER TABLE grades RENAME TO grades__migrate_old;`);
    db.exec(fixedSql);
    db.exec(`INSERT INTO grades (${cols}) SELECT ${cols} FROM grades__migrate_old;`);
    db.exec(`DROP TABLE grades__migrate_old;`);
  });
  migrate();

  db.pragma('foreign_keys = ON');
  db.pragma('legacy_alter_table = OFF');
  console.log('✅ Миграция grades завершена: оценки больше не удаляются при удалении учителя');
})();
// (если база была создана/мигрирована старой версией этого файла, где
// миграция выше выполнялась без legacy_alter_table и успела "сломать"
// внешние ключи в playlists/grades/quizzes/homework_submissions/quiz_results)
// ─────────────────────────────────────────────
(function repairBrokenUsersOldForeignKeys() {
  // БАГ (найден и исправлен): в этот список не были включены library_books и
  // library_playlists — обе таблицы объявляют FOREIGN KEY(...) REFERENCES
  // "users_old"(id), которая после миграции роли operator (см. выше) была
  // переименована обратно в users и удалена. Из-за этого ЛЮБАЯ загрузка
  // книги в библиотеку или создание подборки (плейлиста книг) падали с
  // ошибкой "no such table: main.users_old" — функция сразу ниже умела чинить
  // такие же битые ссылки, но только в перечисленных здесь таблицах.
  const candidateTables = ['playlists', 'homework_submissions', 'grades', 'quizzes', 'quiz_results', 'library_books', 'library_playlists'];
  const broken = candidateTables.filter(t => {
    const row = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name=?").get(t);
    return row && /users_old/.test(row.sql);
  });
  if (!broken.length) return;

  console.warn('⚠️  Обнаружены битые внешние ключи (ссылка на несуществующую users_old) в таблицах:', broken.join(', '));
  console.warn('⚠️  Выполняется автоматическое восстановление схемы...');

  db.pragma('legacy_alter_table = ON');
  db.pragma('foreign_keys = OFF');

  const repair = db.transaction(() => {
    for (const t of broken) {
      const row = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name=?").get(t);
      const fixedSql = row.sql.replace(/"?users_old"?/g, 'users');
      const tmpName  = `${t}__repair_old`;
      db.exec(`ALTER TABLE ${t} RENAME TO ${tmpName};`);
      db.exec(fixedSql);
      const cols = db.prepare(`PRAGMA table_info(${t})`).all().map(c => c.name).join(', ');
      db.exec(`INSERT INTO ${t} (${cols}) SELECT ${cols} FROM ${tmpName};`);
      db.exec(`DROP TABLE ${tmpName};`);
    }
  });
  repair();

  db.pragma('foreign_keys = ON');
  db.pragma('legacy_alter_table = OFF');
  console.log('✅ Внешние ключи восстановлены, данные сохранены:', broken.join(', '));
})();

// ─────────────────────────────────────────────
// НОВЫЕ ТАБЛИЦЫ: факультеты / группы / расписание / прогресс просмотра
// ─────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS faculties (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    description TEXT,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP
  );

  -- Кафедра — входит в факультет
  CREATE TABLE IF NOT EXISTS departments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    description TEXT,
    faculty_id  INTEGER NOT NULL,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(faculty_id) REFERENCES faculties(id) ON DELETE CASCADE
  );

  -- Специальность — входит в кафедру. Курс (1-6) не отдельный узел дерева,
  -- а атрибут конкретной группы (год обучения) — так группы одной
  -- специальности разных лет обучения все лежат внутри неё.
  CREATE TABLE IF NOT EXISTS specialties (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    description   TEXT,
    department_id INTEGER NOT NULL,
    created_at    TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(department_id) REFERENCES departments(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    faculty_id  INTEGER NOT NULL,
    curator_id  INTEGER,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(faculty_id) REFERENCES faculties(id) ON DELETE CASCADE,
    FOREIGN KEY(curator_id) REFERENCES users(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS group_students (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id    INTEGER NOT NULL,
    student_id  INTEGER NOT NULL,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(group_id)   REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY(student_id) REFERENCES users(id)  ON DELETE CASCADE,
    UNIQUE(group_id, student_id)
  );

  CREATE TABLE IF NOT EXISTS group_teachers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id    INTEGER NOT NULL,
    teacher_id  INTEGER NOT NULL,
    playlist_id INTEGER NOT NULL,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(group_id)    REFERENCES groups(id)    ON DELETE CASCADE,
    FOREIGN KEY(teacher_id)  REFERENCES users(id)     ON DELETE CASCADE,
    FOREIGN KEY(playlist_id) REFERENCES playlists(id) ON DELETE CASCADE,
    UNIQUE(group_id, teacher_id, playlist_id)
  );

  CREATE TABLE IF NOT EXISTS schedule (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id      INTEGER NOT NULL,
    playlist_id   INTEGER,
    teacher_id    INTEGER,
    day_of_week   INTEGER,
    lesson_date   TEXT,
    start_time    TEXT NOT NULL,
    end_time      TEXT NOT NULL,
    room          TEXT,
    subject_title TEXT,
    created_at    TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(group_id)    REFERENCES groups(id)    ON DELETE CASCADE,
    FOREIGN KEY(playlist_id) REFERENCES playlists(id) ON DELETE SET NULL,
    FOREIGN KEY(teacher_id)  REFERENCES users(id)      ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS lesson_progress (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id       INTEGER NOT NULL,
    lesson_id        INTEGER NOT NULL,
    watched_seconds  REAL DEFAULT 0,
    duration_seconds REAL DEFAULT 0,
    is_completed     INTEGER DEFAULT 0,
    updated_at       TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(student_id) REFERENCES users(id)   ON DELETE CASCADE,
    FOREIGN KEY(lesson_id)  REFERENCES lessons(id)  ON DELETE CASCADE,
    UNIQUE(student_id, lesson_id)
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER NOT NULL,
    type             TEXT NOT NULL DEFAULT 'grade',
    title            TEXT NOT NULL,
    message          TEXT NOT NULL,
    related_grade_id INTEGER,
    is_read          INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(related_grade_id) REFERENCES grades(id) ON DELETE SET NULL
  );

  -- Видеозвонки: "звезда" вокруг учителя (см. docs) — WebRTC-mesh не масштабируется,
  -- полноценный SFU не вписывается в текущий стек, поэтому учитель выступает хабом.
  CREATE TABLE IF NOT EXISTS video_rooms (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    teacher_id  INTEGER NOT NULL,
    title       TEXT,
    status      TEXT NOT NULL DEFAULT 'active', -- active | ended
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    ended_at    TEXT,
    FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS video_room_groups (
    room_id  INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY (room_id, group_id),
    FOREIGN KEY(room_id)  REFERENCES video_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY(group_id) REFERENCES groups(id)      ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS video_room_participants (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id        INTEGER NOT NULL,
    user_id        INTEGER NOT NULL,
    joined_at      TEXT DEFAULT CURRENT_TIMESTAMP,
    left_at        TEXT,
    mic_enabled    INTEGER DEFAULT 1,
    cam_enabled    INTEGER DEFAULT 1,
    hand_raised    INTEGER DEFAULT 0,
    hand_raised_at TEXT,
    FOREIGN KEY(room_id) REFERENCES video_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id)        ON DELETE CASCADE
  );
`);

db.exec(`CREATE INDEX IF NOT EXISTS idx_video_room_participants_room ON video_room_participants(room_id, user_id)`);

// Индексы под самые частые фильтры/джойны (оценки, сдача ДЗ, результаты тестов,
// прогресс просмотра уроков). Без них SQLite делает полный перебор таблицы —
// незаметно на маленькой базе, но с ростом числа студентов/оценок такие запросы
// (например "все оценки студента X" или "результаты теста Y") начинают тормозить.
db.exec(`CREATE INDEX IF NOT EXISTS idx_grades_student            ON grades(student_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_grades_teacher            ON grades(teacher_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_grades_lesson             ON grades(lesson_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_homework_lesson           ON homework_submissions(lesson_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_homework_student          ON homework_submissions(student_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_quiz_results_quiz         ON quiz_results(quiz_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_quiz_results_student      ON quiz_results(student_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_lesson_progress_student   ON lesson_progress(student_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_lesson_progress_lesson    ON lesson_progress(lesson_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_lessons_playlist          ON lessons(playlist_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_group_students_group      ON group_students(group_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_group_students_student    ON group_students(student_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_group_teachers_group      ON group_teachers(group_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_group_teachers_teacher    ON group_teachers(teacher_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_group_teachers_playlist   ON group_teachers(playlist_id)`);

// Индекс для быстрой выборки непрочитанных уведомлений пользователя
db.exec(`CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read, created_at)`);

// ─────────────────────────────────────────────
// МИГРАЦИЯ КОЛОНОК: 100-балльная система, ИИ-проверка ДЗ, настройка экзаменов
// ─────────────────────────────────────────────
function addColumnIfMissing(table, colDef) {
  const colName = colDef.trim().split(/\s+/)[0];
  const info = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!info.some(c => c.name === colName)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${colDef}`);
  }
}

addColumnIfMissing('grades', 'group_id INTEGER');
addColumnIfMissing('grades', 'playlist_id INTEGER');
addColumnIfMissing('grades', "control_type TEXT DEFAULT 'weekly'");
addColumnIfMissing('grades', 'max_value INTEGER DEFAULT 100');
addColumnIfMissing('grades', "graded_by TEXT DEFAULT 'teacher'");
addColumnIfMissing('grades', 'edited_by INTEGER');
addColumnIfMissing('grades', 'edited_at TEXT');
addColumnIfMissing('grades', 'original_value INTEGER');

// Новая оргструктура: Факультет → Кафедра → Специальность → Группа (курс = год,
// атрибут группы). Колонки nullable — старые группы, созданные до этой
// структуры, остаются "не распределены" (specialty_id = NULL), пока оператор
// не назначит им специальность и курс через новый раздел "Оргструктура".
addColumnIfMissing('groups', 'department_id INTEGER');
addColumnIfMissing('groups', 'specialty_id INTEGER');
addColumnIfMissing('groups', 'course INTEGER'); // 1..6 — год обучения

addColumnIfMissing('homework_submissions', 'ai_grade INTEGER');
addColumnIfMissing('homework_submissions', 'ai_feedback TEXT');
addColumnIfMissing('homework_submissions', "graded_by TEXT DEFAULT 'pending'");
addColumnIfMissing('homework_submissions', 'teacher_overridden INTEGER DEFAULT 0');

addColumnIfMissing('quizzes', 'playlist_id INTEGER');
addColumnIfMissing('quizzes', "control_type TEXT DEFAULT 'lesson'");
addColumnIfMissing('quizzes', 'lesson_id INTEGER'); // тест, привязанный к конкретному уроку (создан из панели урока)
addColumnIfMissing('quizzes', 'max_attempts INTEGER'); // ограничение попыток сдачи, задаётся преподавателем; NULL = без ограничений

// Доступ к книгам библиотеки: приватно (по правилам ниже) / всем / только по прямой ссылке
addColumnIfMissing('library_books', "access_mode TEXT NOT NULL DEFAULT 'private'");
db.exec(`
  CREATE TABLE IF NOT EXISTS library_book_access (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    book_id     INTEGER NOT NULL,
    target_type TEXT NOT NULL CHECK(target_type IN ('student','teacher','group')),
    target_id   INTEGER NOT NULL,
    granted_by  INTEGER,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(book_id)    REFERENCES library_books(id) ON DELETE CASCADE,
    FOREIGN KEY(granted_by) REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE(book_id, target_type, target_id)
  );
`);

// Расширенный профиль студента (для реального учёта в вузе).
// Видят и редактируют: admin, operator и сам студент (свой профиль) — НЕ учитель.
addColumnIfMissing('users', 'iin TEXT');            // ИИН — 12 цифр
addColumnIfMissing('users', 'phone TEXT');           // телефон студента
addColumnIfMissing('users', 'birth_date TEXT');      // дата рождения (YYYY-MM-DD)
addColumnIfMissing('users', 'address TEXT');         // адрес проживания
addColumnIfMissing('users', 'parent_name TEXT');     // ФИО родителя/опекуна
addColumnIfMissing('users', 'parent_phone TEXT');    // телефон родителя/опекуна

// Дедлайн прохождения урока и учёт пропусков
addColumnIfMissing('lessons', 'deadline TEXT');      // ISO-дата, до какого срока нужно пройти урок

// Кто и когда вручную открыл студенту доступ к уроку после истечения дедлайна
db.exec(`
  CREATE TABLE IF NOT EXISTS lesson_access_overrides (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    lesson_id   INTEGER NOT NULL,
    student_id  INTEGER NOT NULL,
    opened_by   INTEGER NOT NULL,
    opened_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(lesson_id)  REFERENCES lessons(id) ON DELETE CASCADE,
    FOREIGN KEY(student_id) REFERENCES users(id)   ON DELETE CASCADE,
    FOREIGN KEY(opened_by)  REFERENCES users(id)   ON DELETE CASCADE,
    UNIQUE(lesson_id, student_id)
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id    INTEGER,
    actor_name  TEXT,
    action      TEXT NOT NULL,
    entity      TEXT NOT NULL,
    entity_id   INTEGER,
    details     TEXT,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS password_reset_requests (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    username     TEXT NOT NULL,
    full_name    TEXT,
    status       TEXT NOT NULL DEFAULT 'pending', -- pending | resolved
    requested_at TEXT DEFAULT CURRENT_TIMESTAMP,
    resolved_by  INTEGER,
    resolved_at  TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)`);

function logAudit(actor, action, entity, entityId, details) {
  try {
    db.prepare(`
      INSERT INTO audit_log (actor_id, actor_name, action, entity, entity_id, details)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(actor?.id ?? null, actor?.full_name ?? actor?.username ?? 'система', action, entity, entityId ?? null,
      details ? JSON.stringify(details) : null);
  } catch (e) {
    console.error('Ошибка записи в audit_log:', e.message);
  }
}

// Создаём администратора по умолчанию если таблица пуста.
// Пароль больше не зашит от "admin123": по умолчанию генерируется случайный
// криптостойкий пароль и печатается в лог один раз. Можно задать
// ADMIN_DEFAULT_PASSWORD в .env, если нужен предсказуемый пароль (например, автоматизированный деплой).
const adminExists = db.prepare('SELECT id FROM users WHERE role = ?').get('admin');
if (!adminExists) {
  const generatedPassword = ADMIN_DEFAULT_PASSWORD || require('crypto').randomBytes(9).toString('base64url');
  const hash = bcrypt.hashSync(generatedPassword, 12);
  db.prepare(`
    INSERT INTO users (username, password_hash, full_name, role)
    VALUES (?, ?, ?, ?)
  `).run('admin', hash, 'Администратор', 'admin');
  console.log('✅ Создан администратор по умолчанию.');
  console.log('   Логин:  admin');
  console.log(`   Пароль: ${generatedPassword}`);
  console.log('   ⚠️  Сохраните пароль сейчас — повторно он не будет показан. Смените его после первого входа.');
}

module.exports = { db, logAudit };
