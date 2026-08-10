'use strict';
require('dotenv').config(); // подгружаем переменные из .env (JWT_SECRET, GROQ_API_KEY, PORT, DATA_DIR)
const express    = require('express');
const bcrypt     = require('bcrypt');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const path       = require('path');
const fs         = require('fs');
const pdfParse   = require('pdf-parse');
const mammoth    = require('mammoth');
const helmet     = require('helmet');
const compression = require('compression');
const rateLimit  = require('express-rate-limit');
const XLSX       = require('xlsx');
const http       = require('http');
const WebSocket  = require('ws');
const r2Storage  = require('./r2-storage');
const { PORT, DATA_DIR, UPLOADS, DB_PATH, JWT_SECRET, GROQ_API_KEY, ADMIN_DEFAULT_PASSWORD } = require('./config');

// Схема БД, миграции, индексы и сид администратора перенесены в ./db/index.js
const { db, logAudit } = require('./db');


// ─────────────────────────────────────────────
// EXPRESS + MIDDLEWARE
// ─────────────────────────────────────────────
const app = express();
const { sendServerError } = require('./middleware/errors');
const { requireAuth } = require('./middleware/auth');

// Важно при доступе через туннель/прокси (ngrok и подобные): без этой
// настройки Express видит все запросы как пришедшие с одного и того же
// адреса (адрес локального прокси-агента), а не с реальных IP пользователей.
// Из-за этого лимитеры запросов ниже (loginLimiter/apiLimiter) считают
// ВСЕХ пользователей, зашедших через ngrok-ссылку, одним "клиентом" —
// и делят один общий лимит на всех, вместо отдельного лимита на каждого.
// При нескольких одновременных пользователях это выглядит как "через
// ngrok-ссылку всё работает медленнее/что-то не грузится", хотя дело не
// в скорости, а в том, что общий лимит запросов исчерпывается в разы
// быстрее, чем при работе с localhost с одного устройства.
app.set('trust proxy', 1);

app.use(helmet({
  // Отключаем дефолтный CSP хелмета — своя статика (video/blob/inline-скрипты в HTML)
  // может конфликтовать с жёсткими правилами по умолчанию. Остальные защитные
  // заголовки (X-Frame-Options, X-Content-Type-Options, HSTS и т.д.) остаются активны.
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
// CORS: пока у вас временный/бесплатный домен, который может смениться —
// оставляем по умолчанию открытым для всех (как и раньше), чтобы ничего не
// сломалось при смене адреса. Когда домен станет постоянным, задайте
// ALLOWED_ORIGINS в .env (через запятую, например
// "https://mydomain.kz,https://www.mydomain.kz") — и CORS будет пускать
// запросы только с этих адресов.
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);
app.use(cors(
  allowedOrigins.length
    ? { origin: allowedOrigins }
    : {}
));

// Сжимаем текстовые/JSON-ответы (HTML/CSS/JS/API) — на медленном канале
// (например через ngrok-туннель) это ощутимо ускоряет загрузку страниц,
// т.к. передаётся в разы меньше байт. Файлы в /uploads (видео, PDF, книги,
// картинки) сюда не попадают — они и так в основном уже сжатые форматы, а
// сжатие на лету сломало бы поддержку Range-запросов (перемотка видео).
app.use(compression({
  filter: (req, res) => {
    if (req.path.startsWith('/uploads')) return false;
    return compression.filter(req, res);
  }
}));

app.use(express.json({ limit: '5mb' }));

// /uploads — загруженные файлы (видео уроков, книги, материалы, аватары и т.д.)
// Имя файла всегда уникально (timestamp + случайное число), т.е. по одному и
// тому же URL никогда не отдаётся другое содержимое — поэтому файл можно
// закэшировать в браузере "навсегда". Раньше кэш-заголовки не выставлялись
// вовсе, и один и тот же видеоурок или книга перекачивались заново при
// каждом открытии — на медленном/туннелированном канале (ngrok и т.п.) это
// был основной источник "тормозов" при загрузке материалов.
app.use('/uploads', express.static(UPLOADS, {
  maxAge: '365d',
  immutable: true,
  etag: true
}));

// Ограничение частоты запросов к логину — защита от подбора пароля (brute-force).
// 15 попыток за 15 минут с одного IP, дальше — временная блокировка.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком много попыток входа. Попробуйте снова через 15 минут.' }
});

// Общий лимит на все API-запросы — защита от перегрузки/DDoS одним клиентом
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком много запросов. Попробуйте немного позже.' }
});
app.use('/api', apiLimiter);

// Отдаём frontend папку как статику.
// /vendor — сторонние библиотеки (A-Frame и т.п., это самые тяжёлые файлы
// в проекте), они не меняются между релизами — кэшируем надолго.
// Остальные файлы (html/css/js) правятся при доработках, поэтому для них
// используем короткий кэш с обязательной ревалидацией по ETag: браузер
// быстро получает 304 Not Modified вместо повторной полной закачки файла,
// если содержимое не изменилось — тоже заметно экономит трафик на
// медленных каналах (ngrok и т.п.), но не покажет пользователю старую
// версию после обновления сервера.
const FRONTEND = path.join(__dirname, 'public');
app.use('/vendor', express.static(path.join(FRONTEND, 'vendor'), {
  maxAge: '30d',
  immutable: true,
  etag: true
}));
app.use(express.static(FRONTEND, {
  maxAge: '5m',
  etag: true
}));

// Загрузка файлов (Multer + проверка "магических байтов") перенесена в ./utils/uploads.js
const {
  uploadLesson, uploadHomework, uploadQuiz, uploadLibraryBook, uploadImport,
  validateUploadSignatures
} = require('./utils/uploads');


// requireAuth теперь приходит из ./middleware/auth (см. импорт выше).

// ─────────────────────────────────────────────
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ─────────────────────────────────────────────
// Удаляет файл с диска если он существует
function deleteFile(filePath) {
  if (!filePath) return;
  const full = path.join(UPLOADS, path.basename(filePath));
  if (fs.existsSync(full)) fs.unlinkSync(full);
}

// Формирует публичный URL для файла
function fileUrl(filePath) {
  if (!filePath) return null;
  return `/uploads/${path.basename(filePath)}`;
}

// ─────────────────────────────────────────────
// ХЕЛПЕРЫ: ГРУППЫ / ДОСТУП К ПЛЕЙЛИСТАМ / ЖУРНАЛ / ИИ-ПРОВЕРКА ДЗ
// ─────────────────────────────────────────────

// Группа, в которой состоит студент (у студента ровно одна группа)
function getStudentGroup(studentId) {
  return db.prepare(`
    SELECT g.* FROM groups g
    JOIN group_students gs ON gs.group_id = g.id
    WHERE gs.student_id = ?
  `).get(studentId) || null;
}

// Есть ли у студента доступ к плейлисту (через привязку группа-учитель-плейлист)
function studentHasPlaylistAccess(studentId, playlistId) {
  const row = db.prepare(`
    SELECT 1 FROM group_students gs
    JOIN group_teachers gt ON gt.group_id = gs.group_id
    WHERE gs.student_id = ? AND gt.playlist_id = ?
    LIMIT 1
  `).get(studentId, playlistId);
  return !!row;
}

// Есть ли у учителя доступ к группе (куратор ИЛИ ведёт предмет в этой группе)
function teacherHasGroupAccess(teacherId, groupId) {
  const row = db.prepare(`
    SELECT 1 FROM groups WHERE id = ? AND curator_id = ?
    UNION
    SELECT 1 FROM group_teachers WHERE group_id = ? AND teacher_id = ?
  `).get(groupId, teacherId, groupId, teacherId);
  return !!row;
}

// Ведёт ли учитель хотя бы один предмет (плейлист) в группе, где состоит этот студент
// (используется, чтобы учитель не мог выставлять оценки произвольным студентам вне своих групп)
function teacherTeachesStudent(teacherId, studentId) {
  const row = db.prepare(`
    SELECT 1 FROM group_students gs
    JOIN group_teachers gt ON gt.group_id = gs.group_id
    WHERE gs.student_id = ? AND gt.teacher_id = ?
    LIMIT 1
  `).get(studentId, teacherId);
  return !!row;
}

// Список ID уроков плейлиста
function getPlaylistLessonIds(playlistId) {
  return db.prepare('SELECT id FROM lessons WHERE playlist_id = ? ORDER BY order_index ASC')
    .all(playlistId).map(r => r.id);
}

// Все ли недельные оценки выставлены студенту по урокам плейлиста
function weeklyComplete(studentId, playlistId) {
  const lessonIds = getPlaylistLessonIds(playlistId);
  if (lessonIds.length === 0) return false;
  const placeholders = lessonIds.map(() => '?').join(',');
  const graded = db.prepare(`
    SELECT COUNT(DISTINCT lesson_id) as c FROM grades
    WHERE student_id = ? AND control_type = 'weekly' AND lesson_id IN (${placeholders})
  `).get(studentId, ...lessonIds).c;
  return graded >= lessonIds.length;
}

function getControlGrade(studentId, playlistId, controlType) {
  return db.prepare(`
    SELECT * FROM grades WHERE student_id = ? AND playlist_id = ? AND control_type = ?
  `).get(studentId, playlistId, controlType);
}

// ─────────────────────────────────────────────
// ДЕДЛАЙНЫ УРОКОВ И ПРОПУСКИ
// ─────────────────────────────────────────────
// Определяет статус доступа студента к уроку с учётом дедлайна.
// Возвращает: { locked, status, deadline, reopened }
//   status: 'no_deadline' | 'in_progress' | 'completed' | 'absence' | 'reopened'
function getLessonAccessStatus(lesson, studentId) {
  if (!lesson.deadline) {
    return { locked: false, status: 'no_deadline', deadline: null, reopened: false };
  }

  const now = new Date();
  const deadline = new Date(lesson.deadline);
  const isPastDeadline = now.getTime() > deadline.getTime();

  if (!isPastDeadline) {
    return { locked: false, status: 'in_progress', deadline: lesson.deadline, reopened: false };
  }

  // Дедлайн прошёл — проверяем, успел ли студент пройти урок / сдать ДЗ
  const progress = db.prepare(`
    SELECT * FROM lesson_progress WHERE student_id = ? AND lesson_id = ?
  `).get(studentId, lesson.id);
  const submission = db.prepare(`
    SELECT * FROM homework_submissions WHERE student_id = ? AND lesson_id = ?
  `).get(studentId, lesson.id);

  const completedInTime =
    (progress && progress.is_completed && new Date(progress.updated_at) <= deadline) ||
    (submission && new Date(submission.submitted_at) <= deadline);

  if (completedInTime) {
    return { locked: false, status: 'completed', deadline: lesson.deadline, reopened: false };
  }

  // Не успел — проверяем, не открыл ли учитель доступ вручную
  const override = db.prepare(`
    SELECT * FROM lesson_access_overrides WHERE lesson_id = ? AND student_id = ?
  `).get(lesson.id, studentId);

  if (override) {
    return { locked: false, status: 'reopened', deadline: lesson.deadline, reopened: true, opened_at: override.opened_at };
  }

  return { locked: true, status: 'absence', deadline: lesson.deadline, reopened: false };
}

// Настроенный экзамен (тест) для данного этапа контроля по плейлисту
function getStageExam(playlistId, controlType) {
  return db.prepare(`
    SELECT * FROM quizzes WHERE playlist_id = ? AND control_type = ?
  `).get(playlistId, controlType);
}

function studentPassedExam(studentId, quizId) {
  // БАГ (найден и исправлен): completed_at хранится как TEXT со стандартной
  // точностью SQLite CURRENT_TIMESTAMP — до секунды. Если студент сдаёт тест
  // несколько раз подряд быстро (в течение одной секунды — например, после
  // ошибки сети или двойного клика), несколько попыток получают ОДИНАКОВЫЙ
  // completed_at, и "ORDER BY completed_at DESC" не гарантирует, что вернётся
  // именно последняя попытка — порядок при равных значениях не определён.
  // Из-за этого итоговая оценка за рубежку/сессию могла считаться по
  // случайной (не обязательно последней) попытке. id — автоинкрементный и
  // всегда монотонно растёт, поэтому сортировка по нему надёжна.
  return db.prepare(`
    SELECT * FROM quiz_results WHERE quiz_id = ? AND student_id = ?
    ORDER BY id DESC LIMIT 1
  `).get(quizId, studentId);
}

// Определяем group_id для оценки по студенту+плейлисту (группа, где этому студенту преподают этот плейлист)
function resolveGroupForStudentPlaylist(studentId, playlistId) {
  const row = db.prepare(`
    SELECT gs.group_id FROM group_students gs
    JOIN group_teachers gt ON gt.group_id = gs.group_id
    WHERE gs.student_id = ? AND gt.playlist_id = ?
    LIMIT 1
  `).get(studentId, playlistId);
  return row ? row.group_id : null;
}

// После сохранения обеих рубежных оценок (и, если настроен, сдачи экзамена сессии) —
// автоматически выставляем итоговую оценку за сессию (если ещё не выставлена вручную)
function maybeCreateSessionGrade(studentId, playlistId) {
  const existing = getControlGrade(studentId, playlistId, 'session');
  if (existing) return existing; // уже выставлена — не перезаписываем автоматически

  const cp1 = getControlGrade(studentId, playlistId, 'checkpoint1');
  const cp2 = getControlGrade(studentId, playlistId, 'checkpoint2');
  if (!cp1 || !cp2) return null;

  const sessionExam = getStageExam(playlistId, 'session');
  let examPercent = null;
  if (sessionExam) {
    const result = studentPassedExam(studentId, sessionExam.id);
    if (!result) return null; // экзамен сессии ещё не сдан — рано считать итог
    examPercent = Math.round((result.score / result.total) * 100);
  }

  const base = (cp1.value + cp2.value) / 2;
  const finalValue = examPercent !== null
    ? Math.round(base * 0.6 + examPercent * 0.4)
    : Math.round(base);

  const groupId = resolveGroupForStudentPlaylist(studentId, playlistId);
  const teacherId = db.prepare('SELECT teacher_id FROM playlists WHERE id = ?').get(playlistId)?.teacher_id;

  const result = db.prepare(`
    INSERT INTO grades (student_id, teacher_id, playlist_id, group_id, control_type, value, max_value, comment, graded_by)
    VALUES (?, ?, ?, ?, 'session', ?, 100, ?, 'auto')
  `).run(studentId, teacherId, playlistId, groupId, finalValue,
    examPercent !== null ? `Автоматически: рубежки (${cp1.value}, ${cp2.value}) + экзамен (${examPercent})` : `Автоматически: среднее рубежек (${cp1.value}, ${cp2.value})`);

  const sessionGrade = db.prepare('SELECT * FROM grades WHERE id = ?').get(result.lastInsertRowid);
  createGradeNotification(sessionGrade, false);
  return sessionGrade;
}

// ─────────────────────────────────────────────
// УВЕДОМЛЕНИЯ
// ─────────────────────────────────────────────
const CONTROL_TYPE_LABELS = {
  weekly:      'за урок',
  checkpoint1: 'за рубежный контроль 1',
  checkpoint2: 'за рубежный контроль 2',
  session:     'итоговая за сессию'
};

// Создаёт уведомление студенту о новой/изменённой оценке.
// gradeRow — строка из таблицы grades (после INSERT/UPDATE).
// isUpdate — true, если оценка была изменена (не создана впервые).
function createGradeNotification(gradeRow, isUpdate = false) {
  try {
    const label = CONTROL_TYPE_LABELS[gradeRow.control_type] || '';
    let subject = '';
    if (gradeRow.lesson_id) {
      const lesson = db.prepare('SELECT title FROM lessons WHERE id = ?').get(gradeRow.lesson_id);
      if (lesson) subject = ` («${lesson.title}»)`;
    } else if (gradeRow.playlist_id) {
      const playlist = db.prepare('SELECT title FROM playlists WHERE id = ?').get(gradeRow.playlist_id);
      if (playlist) subject = ` по курсу «${playlist.title}»`;
    }

    const title = isUpdate ? 'Оценка изменена' : 'Новая оценка';
    const message = isUpdate
      ? `Оценка ${label}${subject} изменена на ${gradeRow.value}.`
      : `Вам выставлена оценка ${gradeRow.value} ${label}${subject}.`;

    db.prepare(`
      INSERT INTO notifications (user_id, type, title, message, related_grade_id)
      VALUES (?, 'grade', ?, ?, ?)
    `).run(gradeRow.student_id, title, message, gradeRow.id);
  } catch (e) {
    // Уведомление не должно ломать основную операцию выставления оценки
    console.error('Ошибка создания уведомления об оценке:', e.message);
  }
}

// Извлечение текста из файла ДЗ (PDF / DOC / DOCX) для передачи в ИИ
async function extractHomeworkText(filePath) {
  const full = path.join(UPLOADS, path.basename(filePath));
  const ext = path.extname(full).toLowerCase();
  try {
    if (ext === '.pdf') {
      const buf = fs.readFileSync(full);
      const data = await pdfParse(buf);
      return (data.text || '').slice(0, 8000);
    } else if (ext === '.docx') {
      const result = await mammoth.extractRawText({ path: full });
      return (result.value || '').slice(0, 8000);
    }
  } catch (e) {
    console.error('Ошибка извлечения текста ДЗ:', e.message);
  }
  return '';
}

// ИИ-проверка домашнего задания через Groq, выставление предварительной оценки
async function aiGradeHomework(submissionId) {
  try {
    const submission = db.prepare(`
      SELECT hs.*, l.title as lesson_title, l.description as lesson_description,
             l.playlist_id, p.teacher_id
      FROM homework_submissions hs
      JOIN lessons l ON l.id = hs.lesson_id
      JOIN playlists p ON p.id = l.playlist_id
      WHERE hs.id = ?
    `).get(submissionId);
    if (!submission) return;

    if (!GROQ_API_KEY) {
      db.prepare(`UPDATE homework_submissions SET graded_by = 'pending' WHERE id = ?`).run(submissionId);
      return;
    }

    const text = await extractHomeworkText(submission.file_path);
    if (!text) {
      // Не удалось извлечь текст (например скан) — оставляем на ручную проверку учителем
      db.prepare(`UPDATE homework_submissions SET graded_by = 'pending' WHERE id = ?`).run(submissionId);
      return;
    }

    const systemPrompt = `Ты — ИИ-проверяющий домашние задания на образовательной платформе ЕдуПортал.
Тема урока: "${submission.lesson_title}".
Описание урока/задания: "${submission.lesson_description || 'не указано'}".
Оцени присланную работу студента по 100-балльной шкале (0-100), где 100 — полное и правильное выполнение.
Ответь СТРОГО в формате JSON без каких-либо пояснений вне JSON:
{"grade": число от 0 до 100, "feedback": "краткий комментарий на русском, 1-3 предложения"}`;

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${GROQ_API_KEY}` },
      body: JSON.stringify({
        model: 'openai/gpt-oss-120b',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: `Текст работы студента:\n\n${text}` }
        ],
        max_tokens: 400,
        temperature: 0.3
      })
    });
    const data = await response.json();
    const raw = data?.choices?.[0]?.message?.content || '';
    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) throw new Error('ИИ не вернул JSON');
    const parsed = JSON.parse(match[0]);
    let grade = Math.round(Number(parsed.grade));
    if (isNaN(grade)) throw new Error('Некорректная оценка от ИИ');
    grade = Math.max(0, Math.min(100, grade));
    const feedback = String(parsed.feedback || '').slice(0, 1000);

    db.prepare(`
      UPDATE homework_submissions
      SET ai_grade = ?, ai_feedback = ?, grade = ?, comment = ?, graded_at = CURRENT_TIMESTAMP, graded_by = 'ai'
      WHERE id = ?
    `).run(grade, feedback, grade, feedback, submissionId);

    // Автоматически выставляем недельную оценку в журнал
    upsertWeeklyGradeFromHomework(submission.student_id, submission.lesson_id, submission.playlist_id, submission.teacher_id, grade, feedback, 'ai');
  } catch (e) {
    console.error('Ошибка ИИ-проверки ДЗ:', e.message);
    db.prepare(`UPDATE homework_submissions SET graded_by = 'pending' WHERE id = ?`).run(submissionId);
  }
}

// Создаёт/обновляет недельную оценку в журнале на основе оценки за ДЗ (от ИИ или учителя)
function upsertWeeklyGradeFromHomework(studentId, lessonId, playlistId, teacherId, value, comment, gradedBy) {
  const groupId = resolveGroupForStudentPlaylist(studentId, playlistId);
  const existing = db.prepare(`
    SELECT * FROM grades WHERE student_id = ? AND lesson_id = ? AND control_type = 'weekly'
  `).get(studentId, lessonId);

  if (existing) {
    const original = existing.original_value !== null ? existing.original_value : existing.value;
    db.prepare(`
      UPDATE grades
      SET value = ?, comment = ?, graded_by = ?, playlist_id = ?, group_id = ?,
          original_value = ?, edited_by = ?, edited_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(value, comment, gradedBy, playlistId, groupId, original, teacherId, existing.id);
  } else {
    db.prepare(`
      INSERT INTO grades (student_id, teacher_id, lesson_id, playlist_id, group_id, control_type, value, max_value, comment, graded_by)
      VALUES (?, ?, ?, ?, ?, 'weekly', ?, 100, ?, ?)
    `).run(studentId, teacherId, lessonId, playlistId, groupId, value, comment, gradedBy);
  }
}

// ─────────────────────────────────────────────
// API: АВТОРИЗАЦИЯ
// ─────────────────────────────────────────────

// POST /api/login — вход в систему
app.post('/api/login', loginLimiter, (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Введите логин и пароль' });

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
    if (!user)
      return res.status(401).json({ error: 'Неверный логин или пароль' });

    const valid = bcrypt.compareSync(String(password).trim(), user.password_hash);
    if (!valid)
      return res.status(401).json({ error: 'Неверный логин или пароль' });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, full_name: user.full_name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token, id: user.id, username: user.username, full_name: user.full_name, role: user.role });
  } catch (e) {
    sendServerError(res, e);
  }
});

// ─────────────────────────────────────────────
// ВОССТАНОВЛЕНИЕ ПАРОЛЯ
// ─────────────────────────────────────────────
// В системе нет email/SMS — поэтому это не полностью самостоятельный сброс,
// а заявка: студент указывает логин, заявка попадает в очередь администрации,
// которая генерирует новый пароль и сообщает его студенту лично/офлайн.

// POST /api/password-reset-request — подать заявку на сброс пароля (без авторизации)
app.post('/api/password-reset-request', loginLimiter, (req, res) => {
  try {
    const { username } = req.body;
    if (!username || !username.trim())
      return res.status(400).json({ error: 'Введите логин' });

    const user = db.prepare('SELECT id, username, full_name FROM users WHERE username = ?').get(username.trim());

    // Намеренно одинаковый ответ независимо от того, найден пользователь или нет —
    // чтобы нельзя было через эту форму проверять, какие логины существуют в системе.
    if (user) {
      const existing = db.prepare(`
        SELECT id FROM password_reset_requests WHERE user_id = ? AND status = 'pending'
      `).get(user.id);
      if (!existing) {
        db.prepare(`
          INSERT INTO password_reset_requests (user_id, username, full_name)
          VALUES (?, ?, ?)
        `).run(user.id, user.username, user.full_name);
      }
    }

    res.json({ success: true, message: 'Заявка отправлена. Дождитесь, пока администрация свяжется с вами и сообщит новый пароль.' });
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/admin/password-reset-requests — очередь заявок (admin, operator)
app.get('/api/admin/password-reset-requests', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const requests = db.prepare(`
      SELECT * FROM password_reset_requests WHERE status = 'pending' ORDER BY requested_at ASC
    `).all();
    res.json(requests);
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/admin/password-reset-requests/:id/resolve — сгенерировать новый пароль и закрыть заявку
app.post('/api/admin/password-reset-requests/:id/resolve', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const reqRow = db.prepare(`SELECT * FROM password_reset_requests WHERE id = ?`).get(req.params.id);
    if (!reqRow) return res.status(404).json({ error: 'Заявка не найдена' });
    if (reqRow.status === 'resolved') return res.status(400).json({ error: 'Заявка уже обработана' });

    const newPassword = generateRandomPassword();
    const hash = bcrypt.hashSync(newPassword, 12);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, reqRow.user_id);
    db.prepare(`
      UPDATE password_reset_requests SET status = 'resolved', resolved_by = ?, resolved_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(req.user.id, req.params.id);

    logAudit(req.user, 'resolve_password_reset', 'user', reqRow.user_id, { username: reqRow.username });

    res.json({ success: true, username: reqRow.username, full_name: reqRow.full_name, new_password: newPassword });
  } catch (e) {
    sendServerError(res, e);
  }
});

// DELETE /api/admin/password-reset-requests/:id — отклонить заявку без сброса пароля
app.delete('/api/admin/password-reset-requests/:id', requireAuth('admin', 'operator'), (req, res) => {
  try {
    db.prepare(`UPDATE password_reset_requests SET status = 'resolved', resolved_by = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?`)
      .run(req.user.id, req.params.id);
    res.json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// ─────────────────────────────────────────────
// API: ПОЛЬЗОВАТЕЛИ
// ─────────────────────────────────────────────

// Поля расширенного профиля студента. Видят/редактируют: admin, operator, сам студент.
// Учителю эти поля никогда не отдаются.
const PROFILE_FIELDS = ['iin', 'phone', 'birth_date', 'address', 'parent_name', 'parent_phone'];

function canSeeProfileFields(req, targetUserId) {
  if (req.user.role === 'admin' || req.user.role === 'operator') return true;
  return req.user.id === parseInt(targetUserId);
}

// GET /api/users — список пользователей с поиском и пагинацией
// ?search=иван&role=student&page=1&limit=30
app.get('/api/users', requireAuth('admin', 'operator', 'teacher'), (req, res) => {
  try {
    const { search = '', role = '' } = req.query;
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit) || 30));
    const offset = (page - 1) * limit;

    const includeProfile = req.user.role === 'admin' || req.user.role === 'operator';
    const cols = includeProfile
      ? `u.id, u.username, u.full_name, u.role, u.created_at, ${PROFILE_FIELDS.map(f => 'u.' + f).join(', ')}`
      : `u.id, u.username, u.full_name, u.role, u.created_at`;
    // БАГ (найден и исправлен): раньше список пользователей не содержал
    // информации о группе студента. Из-за этого форма зачисления в группу
    // (админ-панель) не могла отличить "свободного" студента от уже
    // состоящего в другой группе — предлагала их всех, а POST
    // /api/groups/:id/students затем отклонял такие попытки с 409
    // "Студент уже состоит в другой группе", и выглядело это так, будто
    // зачисление вообще не работает. Добавляем group_id/group_name для
    // admin/operator, чтобы фронтенд мог отфильтровать/показать это заранее.
    const groupJoin = includeProfile
      ? 'LEFT JOIN group_students gs ON gs.student_id = u.id LEFT JOIN groups g ON g.id = gs.group_id'
      : '';
    const groupCols = includeProfile ? ', g.id as group_id, g.name as group_name' : '';

    const where = [];
    const params = [];
    if (search.trim()) {
      where.push('(u.full_name LIKE ? OR u.username LIKE ?)');
      params.push(`%${search.trim()}%`, `%${search.trim()}%`);
    }
    if (role.trim()) {
      where.push('u.role = ?');
      params.push(role.trim());
    }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const total = db.prepare(`SELECT COUNT(*) as c FROM users u ${whereSql}`).get(...params).c;
    const users = db.prepare(`
      SELECT ${cols}${groupCols} FROM users u ${groupJoin} ${whereSql}
      ORDER BY u.created_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    res.json({ users, total, page, limit, pages: Math.max(1, Math.ceil(total / limit)) });
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/users/:id — один пользователь (базовые поля; профильные — только admin/operator/сам)
// ВАЖНО: этот маршрут должен идти ДО '/api/users/:id', иначе Express будет
// перехватывать '/api/users/import-template' и '/api/users/import' как :id="import-template"
// (это и было причиной того, что скачанный шаблон/импорт открывался пустым/битым файлом)
// GET /api/users/export — выгрузить пользователей в Excel (admin, operator).
// Понимает те же ?search= и ?role=, что и список на экране — выгружает то,
// что сейчас отфильтровано в таблице (либо всех, если фильтров нет).
app.get('/api/users/export', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const { search = '', role = '' } = req.query;
    const where = [];
    const params = [];
    if (search.trim()) {
      where.push('(full_name LIKE ? OR username LIKE ?)');
      params.push(`%${search.trim()}%`, `%${search.trim()}%`);
    }
    if (role.trim()) {
      where.push('role = ?');
      params.push(role.trim());
    }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const users = db.prepare(`
      SELECT id, username, full_name, role, created_at, ${PROFILE_FIELDS.join(', ')}
      FROM users ${whereSql}
      ORDER BY created_at DESC
    `).all(...params);

    const ROLE_LABELS_RU = { admin: 'Администратор', operator: 'Оператор', teacher: 'Преподаватель', student: 'Студент' };

    const rows = [
      ['ФИО', 'Логин', 'Роль', 'ИИН', 'Телефон', 'Дата рождения', 'Адрес', 'Родитель', 'Телефон родителя', 'Дата регистрации']
    ];
    users.forEach(u => rows.push([
      u.full_name || '', u.username, ROLE_LABELS_RU[u.role] || u.role,
      u.iin || '', u.phone || '', u.birth_date || '', u.address || '',
      u.parent_name || '', u.parent_phone || '',
      u.created_at ? new Date(u.created_at).toLocaleDateString('ru-RU') : ''
    ]));

    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.aoa_to_sheet(rows);
    ws['!cols'] = [{ wch: 28 }, { wch: 14 }, { wch: 16 }, { wch: 14 }, { wch: 16 }, { wch: 14 }, { wch: 24 }, { wch: 22 }, { wch: 16 }, { wch: 14 }];
    XLSX.utils.book_append_sheet(wb, ws, 'Пользователи');
    const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    logAudit(req.user, 'export_users', 'user', null, { count: users.length, search, role });

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="polzovateli_${new Date().toISOString().slice(0,10)}.xlsx"`);
    res.send(buf);
  } catch (e) {
    sendServerError(res, e);
  }
});

app.get('/api/users/import-template', requireAuth('admin', 'operator'), (req, res) => {
  const rows = [
    ['ФИО', 'Логин', 'Пароль', 'Роль', 'Группа', 'ИИН', 'Телефон', 'Родитель', 'Телефон родителя'],
    ['Иванов Иван Иванович', '', '', 'студент', 'ИС-21', '123456789012', '+77001234567', 'Иванова Мария', '+77007654321'],
    ['Петрова Анна Сергеевна', '', '', 'преподаватель', '', '', '+77001112233', '', '']
  ];
  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet(rows);
  ws['!cols'] = [{ wch: 28 }, { wch: 14 }, { wch: 12 }, { wch: 14 }, { wch: 10 }, { wch: 14 }, { wch: 16 }, { wch: 22 }, { wch: 16 }];
  XLSX.utils.book_append_sheet(wb, ws, 'Пользователи');
  const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename="shablon_import_polzovateley.xlsx"');
  res.send(buf);
});

app.get('/api/users/:id', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    if (req.user.role === 'student' && req.user.id !== parseInt(req.params.id))
      return res.status(403).json({ error: 'Нет доступа' });
    if (req.user.role === 'teacher' && req.user.id !== parseInt(req.params.id))
      return res.status(403).json({ error: 'Нет доступа' });

    const includeProfile = canSeeProfileFields(req, req.params.id);
    const cols = includeProfile
      ? `id, username, full_name, role, created_at, ${PROFILE_FIELDS.join(', ')}`
      : `id, username, full_name, role, created_at`;

    const user = db.prepare(`SELECT ${cols} FROM users WHERE id = ?`).get(req.params.id);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json(user);
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/users — создать пользователя (только admin)
app.post('/api/users', requireAuth('admin'), (req, res) => {
  try {
    const { username, password, full_name, role, iin, phone, birth_date, address, parent_name, parent_phone } = req.body;
    if (!username || !password || !role)
      return res.status(400).json({ error: 'Заполните все обязательные поля' });
    if (!['teacher', 'student', 'admin', 'operator'].includes(role))
      return res.status(400).json({ error: 'Недопустимая роль' });

    const cleanUsername = username.trim();
    if (cleanUsername.length < 3)
      return res.status(400).json({ error: 'Логин минимум 3 символа' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Пароль минимум 6 символов' });

    if (iin && !/^\d{12}$/.test(iin))
      return res.status(400).json({ error: 'ИИН должен состоять из 12 цифр' });
    if (phone && !/^[\d+\-() ]{6,20}$/.test(phone))
      return res.status(400).json({ error: 'Некорректный формат телефона' });
    if (parent_phone && !/^[\d+\-() ]{6,20}$/.test(parent_phone))
      return res.status(400).json({ error: 'Некорректный формат телефона родителя' });
    if (birth_date && !/^\d{4}-\d{2}-\d{2}$/.test(birth_date))
      return res.status(400).json({ error: 'Некорректный формат даты рождения' });

    const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(cleanUsername);
    if (exists)
      return res.status(409).json({ error: 'Пользователь с таким логином уже существует' });

    const hash = bcrypt.hashSync(password, 12);
    const result = db.prepare(`
      INSERT INTO users (username, password_hash, full_name, role, iin, phone, birth_date, address, parent_name, parent_phone)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      cleanUsername, hash, (full_name || '').trim(), role,
      iin || null, phone || null, birth_date || null, address || null, parent_name || null, parent_phone || null
    );

    const user = db.prepare(`
      SELECT id, username, full_name, role, created_at, ${PROFILE_FIELDS.join(', ')}
      FROM users WHERE id = ?
    `).get(result.lastInsertRowid);

    logAudit(req.user, 'create', 'user', user.id, { username: user.username, role: user.role });
    res.status(201).json(user);
  } catch (e) {
    sendServerError(res, e);
  }
});

// PUT /api/users/:id — обновить логин-данные (только admin)
app.put('/api/users/:id', requireAuth('admin'), (req, res) => {
  try {
    const { id } = req.params;
    const { full_name, password } = req.body;

    const user = db.prepare('SELECT id FROM users WHERE id = ?').get(id);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    if (full_name !== undefined) {
      db.prepare('UPDATE users SET full_name = ? WHERE id = ?').run(full_name, id);
    }
    if (password) {
      if (password.length < 6)
        return res.status(400).json({ error: 'Пароль минимум 6 символов' });
      const hash = bcrypt.hashSync(password, 12);
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, id);
    }

    logAudit(req.user, 'update', 'user', parseInt(id), { full_name, password_changed: !!password });

    const updated = db.prepare(`
      SELECT id, username, full_name, role, created_at FROM users WHERE id = ?
    `).get(id);
    res.json(updated);
  } catch (e) {
    sendServerError(res, e);
  }
});

// Транслитерация кириллицы в латиницу для автогенерации логина
const TRANSLIT_MAP = {
  а:'a',б:'b',в:'v',г:'g',д:'d',е:'e',ё:'e',ж:'zh',з:'z',и:'i',й:'y',к:'k',л:'l',
  м:'m',н:'n',о:'o',п:'p',р:'r',с:'s',т:'t',у:'u',ф:'f',х:'h',ц:'ts',ч:'ch',ш:'sh',
  щ:'sch',ъ:'',ы:'y',ь:'',э:'e',ю:'yu',я:'ya'
};
function transliterate(str) {
  return str.toLowerCase().split('').map(ch => TRANSLIT_MAP[ch] ?? ch).join('')
    .replace(/[^a-z0-9]/g, '');
}
function generateUsername(fullName, existingUsernames) {
  const parts = fullName.trim().split(/\s+/).filter(Boolean);
  const base = parts.length >= 2
    ? transliterate(parts[1]) + '.' + transliterate(parts[0]) // имя.фамилия
    : transliterate(parts[0] || 'student');
  let candidate = base || 'student';
  let n = 1;
  while (existingUsernames.has(candidate)) {
    candidate = `${base}${n}`;
    n++;
  }
  existingUsernames.add(candidate);
  return candidate;
}
function generateRandomPassword() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  let pass = '';
  for (let i = 0; i < 10; i++) pass += chars[Math.floor(Math.random() * chars.length)];
  return pass;
}
// Приводит заголовок столбца к нормализованному виду для гибкого сопоставления
function normalizeHeader(h) {
  return String(h || '').toLowerCase().trim().replace(/[^a-zа-яё0-9]/g, '');
}
const IMPORT_COLUMN_MAP = {
  'фио': 'full_name', 'фамилияимя': 'full_name', 'имя': 'full_name',
  'логин': 'username', 'username': 'username',
  'пароль': 'password', 'password': 'password',
  'роль': 'role', 'role': 'role',
  'группа': 'group', 'group': 'group',
  'иин': 'iin',
  'телефон': 'phone', 'телефонстудента': 'phone',
  'родитель': 'parent_name', 'фиородителя': 'parent_name',
  'телефонродителя': 'parent_phone',
  'датарождения': 'birth_date',
  'адрес': 'address'
};

// Гибкое сопоставление роли: и по-русски, и по-английски, и с опечатками в регистре
const IMPORT_ROLE_MAP = {
  'студент': 'student', 'student': 'student', 'ученик': 'student',
  'преподаватель': 'teacher', 'учитель': 'teacher', 'teacher': 'teacher',
  'оператор': 'operator', 'operator': 'operator',
  'администратор': 'admin', 'админ': 'admin', 'admin': 'admin'
};

// POST /api/users/import — массовый импорт пользователей из Excel/CSV (admin, operator).
// Поддерживает любую роль: студент, преподаватель, оператор, администратор —
// либо через столбец "Роль" в самом файле (для каждой строки отдельно),
// либо через выбор роли по умолчанию в форме загрузки (для файлов без этого столбца).
app.post('/api/users/import', requireAuth('admin', 'operator'), (req, res) => {
  uploadImport(req, res, (err) => {
    if (err) return res.status(400).json({ error: 'Ошибка загрузки файла: ' + err.message });
    if (!req.file) return res.status(400).json({ error: 'Файл не прикреплён' });

    try {
      // БАГ (найден и исправлен): XLSX.read(buffer, {type:'buffer'}) для
      // .csv-файлов трактует байты как однобайтовую кодировку (не UTF-8),
      // из-за чего кириллические заголовки вроде "ФИО" превращались в
      // "нечитаемую кашу" ("Ð¤Ð\x98Ð\x9E") и не находились в IMPORT_COLUMN_MAP —
      // импорт всегда падал с "не найден столбец ФИО", даже если файл был
      // полностью корректным. Настоящие .xlsx/.xls остаются бинарными (zip),
      // их по-прежнему нужно читать как buffer; только .csv нужно сначала
      // раскодировать как текст UTF-8.
      const isCsv = /\.csv$/i.test(req.file.originalname || '');
      const wb = isCsv
        ? XLSX.read(req.file.buffer.toString('utf8'), { type: 'string' })
        : XLSX.read(req.file.buffer, { type: 'buffer' });
      const sheet = wb.Sheets[wb.SheetNames[0]];
      const rawRows = XLSX.utils.sheet_to_json(sheet, { defval: '' });
      if (!rawRows.length) return res.status(400).json({ error: 'Файл пуст или не удалось прочитать данные' });

      // Роль по умолчанию для строк без столбца "Роль" (или с пустым значением
      // в нём) — приходит из формы загрузки. Если не передана — 'student',
      // как и раньше.
      const defaultRole = ['student', 'teacher', 'operator', 'admin'].includes(req.body.default_role)
        ? req.body.default_role : 'student';

      // Сопоставляем заголовки файла с нашими полями
      const firstRowKeys = Object.keys(rawRows[0]);
      const keyMap = {}; // исходный ключ -> наше поле
      firstRowKeys.forEach(k => {
        const norm = normalizeHeader(k);
        if (IMPORT_COLUMN_MAP[norm]) keyMap[k] = IMPORT_COLUMN_MAP[norm];
      });
      if (!Object.values(keyMap).includes('full_name'))
        return res.status(400).json({ error: 'В файле не найден столбец "ФИО". Скачайте шаблон и заполните по образцу.' });

      const existingUsernames = new Set(
        db.prepare('SELECT username FROM users').all().map(u => u.username)
      );
      const groupsCache = new Map(
        db.prepare('SELECT id, name FROM groups').all().map(g => [g.name.toLowerCase().trim(), g.id])
      );

      const insertUser = db.prepare(`
        INSERT INTO users (username, password_hash, full_name, role)
        VALUES (?, ?, ?, ?)
      `);
      const insertProfile = db.prepare(`
        UPDATE users SET iin = ?, phone = ?, parent_name = ?, parent_phone = ?, birth_date = ?, address = ?
        WHERE id = ?
      `);
      const enrollStudent = db.prepare(`
        INSERT OR IGNORE INTO group_students (group_id, student_id) VALUES (?, ?)
      `);

      const created = [];
      const errors = [];

      const importAll = db.transaction((rows) => {
        rows.forEach((raw, idx) => {
          const row = {};
          Object.entries(raw).forEach(([k, v]) => {
            if (keyMap[k]) row[keyMap[k]] = String(v ?? '').trim();
          });

          const rowNum = idx + 2; // +2: с учётом заголовка и нумерации с 1
          const fullName = row.full_name;
          if (!fullName) { errors.push({ row: rowNum, error: 'Не указано ФИО' }); return; }

          // Роль строки: берём из столбца "Роль", если он есть и распознан;
          // иначе — роль по умолчанию, выбранная в форме загрузки.
          let role = defaultRole;
          if (row.role) {
            const mapped = IMPORT_ROLE_MAP[row.role.toLowerCase().trim()];
            if (mapped) role = mapped;
            else { errors.push({ row: rowNum, error: `Роль "${row.role}" не распознана, использована роль по умолчанию` }); }
          }

          let username = row.username || generateUsername(fullName, existingUsernames);
          username = username.toLowerCase();
          if (existingUsernames.has(username) && row.username) {
            errors.push({ row: rowNum, error: `Логин "${username}" уже занят` });
            return;
          }
          existingUsernames.add(username);

          if (row.iin && !/^\d{12}$/.test(row.iin)) {
            errors.push({ row: rowNum, error: 'ИИН должен состоять из 12 цифр — строка пропущена частично (пользователь создан без ИИН)' });
            row.iin = '';
          }

          const password = row.password || generateRandomPassword();
          const hash = bcrypt.hashSync(password, 12);

          const result = insertUser.run(username, hash, fullName, role);
          const userId = result.lastInsertRowid;

          insertProfile.run(
            row.iin || null, row.phone || null, row.parent_name || null,
            row.parent_phone || null, row.birth_date || null, row.address || null,
            userId
          );

          // Зачисление в группу имеет смысл только для студентов.
          if (row.group && role === 'student') {
            const groupId = groupsCache.get(row.group.toLowerCase().trim());
            if (groupId) enrollStudent.run(groupId, userId);
            else errors.push({ row: rowNum, error: `Группа "${row.group}" не найдена — студент создан, но не зачислен` });
          }

          created.push({ row: rowNum, full_name: fullName, username, role, password: row.password ? null : password });
        });
      });

      importAll(rawRows);

      logAudit(req.user, 'bulk_import', 'user', null, { created: created.length, errors: errors.length });

      res.json({ created, errors, total: rawRows.length });
    } catch (e) {
      console.error('[server error]', e);
      res.status(500).json({ error: 'Ошибка обработки файла: ' + e.message });
    }
  });
});

// PUT /api/me/credentials — пользователь сам меняет свой логин и/или пароль
// (нужен текущий пароль для подтверждения). Доступно любой роли — раньше
// логин и пароль мог поменять только администратор через панель.
app.put('/api/me/credentials', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    const { current_password, new_username, new_password } = req.body;
    if (!current_password)
      return res.status(400).json({ error: 'Введите текущий пароль для подтверждения' });

    const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!me) return res.status(404).json({ error: 'Пользователь не найден' });

    const valid = bcrypt.compareSync(current_password, me.password_hash);
    if (!valid) return res.status(401).json({ error: 'Текущий пароль указан неверно' });

    if (!new_username && !new_password)
      return res.status(400).json({ error: 'Укажите новый логин или новый пароль' });

    let username = me.username;
    if (new_username && new_username.trim() && new_username.trim() !== me.username) {
      username = new_username.trim();
      if (username.length < 3)
        return res.status(400).json({ error: 'Логин минимум 3 символа' });
      if (!/^[a-zA-Z0-9_]+$/.test(username))
        return res.status(400).json({ error: 'Логин может содержать только латинские буквы, цифры и подчёркивание' });
      const exists = db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').get(username, me.id);
      if (exists) return res.status(409).json({ error: 'Такой логин уже занят' });
      db.prepare('UPDATE users SET username = ? WHERE id = ?').run(username, me.id);
    }

    if (new_password) {
      if (new_password.length < 6)
        return res.status(400).json({ error: 'Новый пароль минимум 6 символов' });
      const hash = bcrypt.hashSync(new_password, 12);
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, me.id);
    }

    logAudit(req.user, 'update_profile', 'user', me.id, { self_service: true, username_changed: username !== me.username, password_changed: !!new_password });

    // Логин мог измениться — перевыпускаем токен, чтобы сессия осталась рабочей.
    const token = jwt.sign(
      { id: me.id, username, role: me.role, full_name: me.full_name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token, id: me.id, username, full_name: me.full_name, role: me.role });
  } catch (e) {
    sendServerError(res, e);
  }
});


// Доступ: admin, operator, сам пользователь. Учителю — запрещено.
app.get('/api/users/:id/profile', requireAuth('admin', 'operator', 'student'), (req, res) => {
  try {
    if (!canSeeProfileFields(req, req.params.id))
      return res.status(403).json({ error: 'Нет доступа к этим данным' });

    const user = db.prepare(`
      SELECT id, full_name, ${PROFILE_FIELDS.join(', ')} FROM users WHERE id = ?
    `).get(req.params.id);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json(user);
  } catch (e) {
    sendServerError(res, e);
  }
});

app.put('/api/users/:id/profile', requireAuth('admin', 'operator', 'student'), (req, res) => {
  try {
    if (!canSeeProfileFields(req, req.params.id))
      return res.status(403).json({ error: 'Нет доступа к этим данным' });

    const target = db.prepare('SELECT id FROM users WHERE id = ?').get(req.params.id);
    if (!target) return res.status(404).json({ error: 'Пользователь не найден' });

    const { iin, phone, birth_date, address, parent_name, parent_phone } = req.body;

    if (iin !== undefined && iin !== '' && !/^\d{12}$/.test(iin))
      return res.status(400).json({ error: 'ИИН должен состоять из 12 цифр' });
    if (phone !== undefined && phone !== '' && !/^[\d+\-() ]{6,20}$/.test(phone))
      return res.status(400).json({ error: 'Некорректный формат телефона' });
    if (parent_phone !== undefined && parent_phone !== '' && !/^[\d+\-() ]{6,20}$/.test(parent_phone))
      return res.status(400).json({ error: 'Некорректный формат телефона родителя' });
    if (birth_date !== undefined && birth_date !== '' && !/^\d{4}-\d{2}-\d{2}$/.test(birth_date))
      return res.status(400).json({ error: 'Некорректный формат даты рождения' });

    db.prepare(`
      UPDATE users SET
        iin = COALESCE(?, iin), phone = COALESCE(?, phone), birth_date = COALESCE(?, birth_date),
        address = COALESCE(?, address), parent_name = COALESCE(?, parent_name), parent_phone = COALESCE(?, parent_phone)
      WHERE id = ?
    `).run(
      iin ?? null, phone ?? null, birth_date ?? null, address ?? null, parent_name ?? null, parent_phone ?? null,
      req.params.id
    );

    logAudit(req.user, 'update_profile', 'user', parseInt(req.params.id), { fields: Object.keys(req.body) });

    const updated = db.prepare(`
      SELECT id, full_name, ${PROFILE_FIELDS.join(', ')} FROM users WHERE id = ?
    `).get(req.params.id);
    res.json(updated);
  } catch (e) {
    sendServerError(res, e);
  }
});

// DELETE /api/users/:id — удалить пользователя
app.delete('/api/users/:id', requireAuth('admin'), (req, res) => {
  try {
    const { id } = req.params;
    if (parseInt(id) === req.user.id)
      return res.status(400).json({ error: 'Нельзя удалить самого себя' });

    const user = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(id);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    // БАГ (найден и исправлен): у преподавателя playlists.teacher_id объявлен
    // как "ON DELETE CASCADE" — удаление аккаунта учителя без предупреждения
    // безвозвратно удаляло ВСЕ его курсы, уроки (включая видео/материалы),
    // тесты и, как следствие, результаты тестов и домашние задания студентов
    // по этим курсам (только сами оценки в таблице grades сохранялись —
    // остальной учебный контент и связанные записи студентов пропадали
    // без возможности восстановления). Теперь удаление блокируется, пока
    // за преподавателем числятся курсы — администратору нужно сначала
    // удалить или передать эти курсы другому преподавателю.
    if (user.role === 'teacher') {
      const ownedPlaylists = db.prepare('SELECT id, title FROM playlists WHERE teacher_id = ?').all(id);
      if (ownedPlaylists.length) {
        return res.status(409).json({
          error: `Нельзя удалить преподавателя — за ним закреплено курсов: ${ownedPlaylists.length} `
               + `(${ownedPlaylists.map(p => p.title).join(', ')}). Сначала удалите эти курсы или `
               + `переназначьте их другому преподавателю — иначе вместе с преподавателем безвозвратно `
               + `удалятся все уроки, видео, тесты и результаты студентов по этим курсам.`,
          playlists: ownedPlaylists
        });
      }
    }

    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    logAudit(req.user, 'delete', 'user', parseInt(id), { username: user.username, role: user.role });
    res.json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// ─────────────────────────────────────────────
// API: ПЛЕЙЛИСТЫ
// ─────────────────────────────────────────────

// GET /api/playlists — список плейлистов с уроками
app.get('/api/playlists', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    let playlists;

    if (req.user.role === 'teacher') {
      // Учитель видит только свои плейлисты
      playlists = db.prepare(`
        SELECT p.*, u.full_name as teacher_name
        FROM playlists p
        JOIN users u ON u.id = p.teacher_id
        WHERE p.teacher_id = ?
        ORDER BY p.created_at DESC
      `).all(req.user.id);
    } else if (req.user.role === 'student') {
      // Студент видит только плейлисты, назначенные его группе оператором
      playlists = db.prepare(`
        SELECT DISTINCT p.*, u.full_name as teacher_name
        FROM playlists p
        JOIN users u ON u.id = p.teacher_id
        JOIN group_teachers gt ON gt.playlist_id = p.id
        JOIN group_students gs ON gs.group_id = gt.group_id
        WHERE gs.student_id = ?
        ORDER BY p.created_at DESC
      `).all(req.user.id);
    } else {
      // Админ и оператор видят все плейлисты
      playlists = db.prepare(`
        SELECT p.*, u.full_name as teacher_name
        FROM playlists p
        JOIN users u ON u.id = p.teacher_id
        ORDER BY p.created_at DESC
      `).all();
    }

    // Добавляем уроки к каждому плейлисту (+ информация о привязанном тесте, если есть)
    const getLessons = db.prepare(`
      SELECT l.id, l.playlist_id, l.title, l.description, l.order_index, l.created_at, l.deadline,
             l.video_2d_path, l.video_vr_path, l.material_path,
             CASE WHEN l.video_2d_path IS NOT NULL THEN 1 ELSE 0 END as has_video_2d,
             CASE WHEN l.video_vr_path IS NOT NULL THEN 1 ELSE 0 END as has_video_vr,
             CASE WHEN l.material_path IS NOT NULL THEN 1 ELSE 0 END as has_material,
             q.id as quiz_id,
             (SELECT COUNT(*) FROM quiz_questions qq WHERE qq.quiz_id = q.id) as quiz_question_count
      FROM lessons l
      LEFT JOIN quizzes q ON q.lesson_id = l.id
      WHERE l.playlist_id = ?
      ORDER BY l.order_index ASC
    `);

    for (const pl of playlists) {
      pl.lessons = getLessons.all(pl.id);
      if (req.user.role === 'student') {
        pl.lessons.forEach(l => {
          const access = l.deadline ? getLessonAccessStatus(l, req.user.id) : null;
          l.locked = access ? access.locked : false;
          l.attendance = access ? access.status : 'no_deadline';
        });
      }
    }

    res.json(playlists);
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/playlists — создать плейлист (только учитель)
app.post('/api/playlists', requireAuth('teacher'), (req, res) => {
  try {
    const { title, description } = req.body;
    if (!title) return res.status(400).json({ error: 'Название обязательно' });

    const result = db.prepare(`
      INSERT INTO playlists (title, description, teacher_id)
      VALUES (?, ?, ?)
    `).run(title, description || '', req.user.id);

    const playlist = db.prepare(`
      SELECT p.*, u.full_name as teacher_name
      FROM playlists p
      JOIN users u ON u.id = p.teacher_id
      WHERE p.id = ?
    `).get(result.lastInsertRowid);

    playlist.lessons = [];
    res.status(201).json(playlist);
  } catch (e) {
    sendServerError(res, e);
  }
});

// PUT /api/playlists/:id — обновить плейлист
app.put('/api/playlists/:id', requireAuth('teacher'), (req, res) => {
  try {
    const { id } = req.params;
    const { title, description } = req.body;

    const playlist = db.prepare(
      'SELECT id FROM playlists WHERE id = ? AND teacher_id = ?'
    ).get(id, req.user.id);
    if (!playlist)
      return res.status(404).json({ error: 'Плейлист не найден или нет доступа' });

    db.prepare(`
      UPDATE playlists SET title = ?, description = ? WHERE id = ?
    `).run(title, description || '', id);

    res.json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// DELETE /api/playlists/:id — удалить плейлист
app.delete('/api/playlists/:id', requireAuth('teacher', 'admin'), (req, res) => {
  try {
    const { id } = req.params;
    const playlist = db.prepare('SELECT id, teacher_id FROM playlists WHERE id = ?').get(id);
    if (!playlist) return res.status(404).json({ error: 'Плейлист не найден' });

    // Учитель может удалять только свои плейлисты, админ — любые
    if (req.user.role === 'teacher' && playlist.teacher_id !== req.user.id)
      return res.status(403).json({ error: 'Нет доступа' });

    db.prepare('DELETE FROM playlists WHERE id = ?').run(id);
    res.json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// ─────────────────────────────────────────────
// API: УРОКИ
// ─────────────────────────────────────────────

// POST /api/lessons — создать урок с файлами (только учитель)
app.post('/api/lessons', requireAuth('teacher'), (req, res) => {
  uploadLesson(req, res, (err) => {
    if (err) return res.status(400).json({ error: 'Ошибка загрузки файла: ' + err.message });

    try {
      const { playlist_id, title, description, order_index, deadline } = req.body;
      if (!playlist_id || !title)
        return res.status(400).json({ error: 'playlist_id и title обязательны' });
      if (deadline && isNaN(new Date(deadline).getTime()))
        return res.status(400).json({ error: 'Некорректный формат срока прохождения' });

      // Проверяем что плейлист принадлежит этому учителю
      const playlist = db.prepare(
        'SELECT id FROM playlists WHERE id = ? AND teacher_id = ?'
      ).get(playlist_id, req.user.id);
      if (!playlist)
        return res.status(403).json({ error: 'Нет доступа к этому плейлисту' });

      const files   = req.files || {};
      const v2d     = files.video_2d  ? fileUrl(files.video_2d[0].filename)  : null;
      const vvr     = files.video_vr  ? fileUrl(files.video_vr[0].filename)  : null;
      const mat     = files.material  ? fileUrl(files.material[0].filename)  : null;

      // Определяем порядок урока
      const maxOrder = db.prepare(
        'SELECT MAX(order_index) as m FROM lessons WHERE playlist_id = ?'
      ).get(playlist_id);
      const idx = order_index !== undefined
        ? parseInt(order_index)
        : (maxOrder.m !== null ? maxOrder.m + 1 : 0);

      const result = db.prepare(`
        INSERT INTO lessons
          (playlist_id, title, description, video_2d_path, video_vr_path, material_path, order_index, deadline)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(playlist_id, title, description || '', v2d, vvr, mat, idx, deadline || null);

      const lesson = db.prepare('SELECT * FROM lessons WHERE id = ?')
        .get(result.lastInsertRowid);

      res.status(201).json(lesson);
    } catch (e) {
      sendServerError(res, e);
    }
  });
});

// GET /api/lessons/:id — получить один урок
app.get('/api/lessons/:id', requireAuth('admin', 'teacher', 'student'), (req, res) => {
  try {
    const lesson = db.prepare('SELECT * FROM lessons WHERE id = ?').get(req.params.id);
    if (!lesson) return res.status(404).json({ error: 'Урок не найден' });

    const quiz = db.prepare(`
      SELECT id, title, (SELECT COUNT(*) FROM quiz_questions qq WHERE qq.quiz_id = quizzes.id) as question_count
      FROM quizzes WHERE lesson_id = ?
    `).get(lesson.id);
    lesson.quiz = quiz || null;

    if (req.user.role === 'student') {
      // Студент может открыть только урок из плейлиста, назначенного его группе
      if (!studentHasPlaylistAccess(req.user.id, lesson.playlist_id))
        return res.status(403).json({ error: 'Нет доступа к этому уроку' });

      const access = getLessonAccessStatus(lesson, req.user.id);
      if (access.locked) {
        return res.status(423).json({
          error: 'Срок прохождения урока истёк. Доступ закрыт — обратитесь к преподавателю.',
          locked: true,
          deadline: access.deadline
        });
      }
      return res.json({ ...lesson, access });
    }

    res.json(lesson);
  } catch (e) {
    sendServerError(res, e);
  }
});

// PUT /api/lessons/:id — обновить урок
app.put('/api/lessons/:id', requireAuth('teacher'), (req, res) => {
  uploadLesson(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    try {
      const { id } = req.params;
      const lesson = db.prepare(`
        SELECT l.* FROM lessons l
        JOIN playlists p ON p.id = l.playlist_id
        WHERE l.id = ? AND p.teacher_id = ?
      `).get(id, req.user.id);
      if (!lesson) return res.status(404).json({ error: 'Урок не найден или нет доступа' });

      const { title, description, deadline, clear_deadline } = req.body;
      if (deadline && isNaN(new Date(deadline).getTime()))
        return res.status(400).json({ error: 'Некорректный формат срока прохождения' });
      const files = req.files || {};

      let v2d = lesson.video_2d_path;
      let vvr = lesson.video_vr_path;
      let mat = lesson.material_path;

      if (files.video_2d) { deleteFile(lesson.video_2d_path); v2d = fileUrl(files.video_2d[0].filename); }
      if (files.video_vr) { deleteFile(lesson.video_vr_path); vvr = fileUrl(files.video_vr[0].filename); }
      if (files.material) { deleteFile(lesson.material_path); mat = fileUrl(files.material[0].filename); }

      const newDeadline = clear_deadline === 'true' || clear_deadline === true
        ? null
        : (deadline !== undefined ? (deadline || null) : lesson.deadline);

      db.prepare(`
        UPDATE lessons
        SET title = ?, description = ?, video_2d_path = ?, video_vr_path = ?, material_path = ?, deadline = ?
        WHERE id = ?
      `).run(title || lesson.title, description || lesson.description, v2d, vvr, mat, newDeadline, id);

      res.json(db.prepare('SELECT * FROM lessons WHERE id = ?').get(id));
    } catch (e) {
      sendServerError(res, e);
    }
  });
});

// DELETE /api/lessons/:id — удалить урок
app.delete('/api/lessons/:id', requireAuth('teacher', 'admin'), (req, res) => {
  try {
    const lesson = db.prepare(`
      SELECT l.*, p.teacher_id as playlist_teacher_id
      FROM lessons l
      JOIN playlists p ON p.id = l.playlist_id
      WHERE l.id = ?
    `).get(req.params.id);
    if (!lesson) return res.status(404).json({ error: 'Урок не найден' });

    // Учитель может удалять только уроки из своих плейлистов, админ — любые
    if (req.user.role === 'teacher' && lesson.playlist_teacher_id !== req.user.id)
      return res.status(403).json({ error: 'Нет доступа' });

    // Удаляем файлы с диска
    deleteFile(lesson.video_2d_path);
    deleteFile(lesson.video_vr_path);
    deleteFile(lesson.material_path);

    db.prepare('DELETE FROM lessons WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/lessons/:id/reopen — учитель открывает доступ студенту после истёкшего дедлайна
app.post('/api/lessons/:id/reopen', requireAuth('teacher'), (req, res) => {
  try {
    const { student_id } = req.body;
    if (!student_id) return res.status(400).json({ error: 'student_id обязателен' });

    const lesson = db.prepare(`
      SELECT l.* FROM lessons l
      JOIN playlists p ON p.id = l.playlist_id
      WHERE l.id = ? AND p.teacher_id = ?
    `).get(req.params.id, req.user.id);
    if (!lesson) return res.status(404).json({ error: 'Урок не найден или нет доступа' });

    db.prepare(`
      INSERT INTO lesson_access_overrides (lesson_id, student_id, opened_by)
      VALUES (?, ?, ?)
      ON CONFLICT(lesson_id, student_id) DO UPDATE SET opened_by = excluded.opened_by, opened_at = CURRENT_TIMESTAMP
    `).run(req.params.id, student_id, req.user.id);

    logAudit(req.user, 'reopen_lesson_access', 'lesson', parseInt(req.params.id), { student_id });

    // Уведомляем студента, что доступ снова открыт
    try {
      db.prepare(`
        INSERT INTO notifications (user_id, type, title, message)
        VALUES (?, 'access', ?, ?)
      `).run(student_id, 'Доступ к уроку открыт', `Преподаватель открыл вам доступ к уроку «${lesson.title}» после истечения срока.`);
    } catch (e) { /* не критично */ }

    res.json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// DELETE /api/lessons/:id/reopen/:student_id — отозвать ранее выданный доступ (снова закрыть урок)
app.delete('/api/lessons/:id/reopen/:student_id', requireAuth('teacher'), (req, res) => {
  try {
    const lesson = db.prepare(`
      SELECT l.* FROM lessons l
      JOIN playlists p ON p.id = l.playlist_id
      WHERE l.id = ? AND p.teacher_id = ?
    `).get(req.params.id, req.user.id);
    if (!lesson) return res.status(404).json({ error: 'Урок не найден или нет доступа' });

    db.prepare(`
      DELETE FROM lesson_access_overrides WHERE lesson_id = ? AND student_id = ?
    `).run(req.params.id, req.params.student_id);

    logAudit(req.user, 'revoke_lesson_access', 'lesson', parseInt(req.params.id), { student_id: req.params.student_id });
    res.json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/lessons/:id/access — статус доступа всех студентов группы к уроку (для учителя)
app.get('/api/lessons/:id/access', requireAuth('teacher', 'admin'), (req, res) => {
  try {
    const { group_id } = req.query;
    if (!group_id) return res.status(400).json({ error: 'group_id обязателен' });

    const lesson = db.prepare('SELECT * FROM lessons WHERE id = ?').get(req.params.id);
    if (!lesson) return res.status(404).json({ error: 'Урок не найден' });

    if (req.user.role === 'teacher') {
      const owns = db.prepare(`
        SELECT 1 FROM playlists WHERE id = ? AND teacher_id = ?
      `).get(lesson.playlist_id, req.user.id);
      if (!owns) return res.status(403).json({ error: 'Нет доступа' });
    }

    const students = db.prepare(`
      SELECT u.id, u.full_name FROM group_students gs
      JOIN users u ON u.id = gs.student_id
      WHERE gs.group_id = ?
      ORDER BY u.full_name ASC
    `).all(group_id);

    const result = students.map(st => ({
      student: st,
      access: getLessonAccessStatus(lesson, st.id)
    }));

    res.json({ deadline: lesson.deadline, students: result });
  } catch (e) {
    sendServerError(res, e);
  }
});
// ─────────────────────────────────────────────
// API: ДОМАШНИЕ ЗАДАНИЯ
// ─────────────────────────────────────────────

// POST /api/homework — сдать домашнее задание (только студент)
app.post('/api/homework', requireAuth('student'), (req, res) => {
  uploadHomework(req, res, (err) => {
    if (err) return res.status(400).json({ error: 'Ошибка загрузки: ' + err.message });
    if (req.file) {
      const sigErr = validateUploadSignatures([req.file]);
      if (sigErr) return res.status(400).json({ error: sigErr });
    }

    try {
      const { lesson_id } = req.body;
      if (!lesson_id) return res.status(400).json({ error: 'lesson_id обязателен' });
      if (!req.file)  return res.status(400).json({ error: 'Файл не прикреплён' });

      // Гейт: нельзя сдать ДЗ, пока видео урока не досмотрено до конца
      const lessonRow = db.prepare('SELECT * FROM lessons WHERE id = ?').get(lesson_id);
      if (!lessonRow) { deleteFile(fileUrl(req.file.filename)); return res.status(404).json({ error: 'Урок не найден' }); }

      if (!studentHasPlaylistAccess(req.user.id, lessonRow.playlist_id)) {
        deleteFile(fileUrl(req.file.filename));
        return res.status(403).json({ error: 'Нет доступа к этому уроку' });
      }

      // Гейт: если срок прохождения истёк и доступ не открыт учителем — ДЗ не принимается
      const access = getLessonAccessStatus(lessonRow, req.user.id);
      if (access.locked) {
        deleteFile(fileUrl(req.file.filename));
        return res.status(423).json({ error: 'Срок прохождения урока истёк. Доступ закрыт — обратитесь к преподавателю.' });
      }

      if (lessonRow.video_2d_path) {
        const progress = db.prepare(`
          SELECT is_completed FROM lesson_progress WHERE student_id = ? AND lesson_id = ?
        `).get(req.user.id, lesson_id);
        if (!progress || !progress.is_completed) {
          deleteFile(fileUrl(req.file.filename));
          return res.status(403).json({ error: 'Досмотрите видео урока до конца, чтобы открыть отправку домашнего задания' });
        }
      }

      const filePath = fileUrl(req.file.filename);

      // Проверяем — сдавал ли уже этот студент Д/З по этому уроку
      const existing = db.prepare(`
        SELECT id, file_path FROM homework_submissions
        WHERE lesson_id = ? AND student_id = ?
      `).get(lesson_id, req.user.id);

      let submissionId;
      if (existing) {
        // Перезаписываем: удаляем старый файл, обновляем запись
        deleteFile(existing.file_path);
        db.prepare(`
          UPDATE homework_submissions
          SET file_path = ?, submitted_at = CURRENT_TIMESTAMP,
              grade = NULL, ai_grade = NULL, ai_feedback = NULL, graded_by = 'pending',
              teacher_overridden = 0, graded_at = NULL, comment = NULL
          WHERE id = ?
        `).run(filePath, existing.id);
        submissionId = existing.id;
      } else {
        // Новая сдача
        const result = db.prepare(`
          INSERT INTO homework_submissions (lesson_id, student_id, file_path)
          VALUES (?, ?, ?)
        `).run(lesson_id, req.user.id, filePath);
        submissionId = result.lastInsertRowid;
      }

      // Запускаем ИИ-проверку (не блокируем ответ студенту надолго)
      aiGradeHomework(submissionId).catch(e => console.error('AI grade error:', e.message));

      const submission = db.prepare(`
        SELECT hs.*, u.full_name as student_name, l.title as lesson_title
        FROM homework_submissions hs
        JOIN users u   ON u.id  = hs.student_id
        JOIN lessons l ON l.id  = hs.lesson_id
        WHERE hs.id = ?
      `).get(submissionId);

      res.status(201).json(submission);
    } catch (e) {
      sendServerError(res, e);
    }
  });
});

// POST /api/lessons/:id/progress — обновить прогресс просмотра видео (студент)
app.post('/api/lessons/:id/progress', requireAuth('student'), (req, res) => {
  try {
    const lessonId = req.params.id;
    const { watched_seconds, duration_seconds } = req.body;
    const watched  = Number(watched_seconds)  || 0;
    const duration = Number(duration_seconds) || 0;

    const lesson = db.prepare('SELECT id, playlist_id FROM lessons WHERE id = ?').get(lessonId);
    if (!lesson) return res.status(404).json({ error: 'Урок не найден' });
    if (!studentHasPlaylistAccess(req.user.id, lesson.playlist_id))
      return res.status(403).json({ error: 'Нет доступа к этому уроку' });

    const existing = db.prepare(`
      SELECT * FROM lesson_progress WHERE student_id = ? AND lesson_id = ?
    `).get(req.user.id, lessonId);

    // Не даём "откатить" прогресс назад и не даём понизить is_completed после того как он уже true
    const maxWatched = existing ? Math.max(existing.watched_seconds, watched) : watched;
    const isCompleted = (existing && existing.is_completed) ||
      (duration > 0 && maxWatched >= duration * 0.9) ? 1 : 0;

    if (existing) {
      db.prepare(`
        UPDATE lesson_progress
        SET watched_seconds = ?, duration_seconds = ?, is_completed = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(maxWatched, duration || existing.duration_seconds, isCompleted, existing.id);
    } else {
      db.prepare(`
        INSERT INTO lesson_progress (student_id, lesson_id, watched_seconds, duration_seconds, is_completed)
        VALUES (?, ?, ?, ?, ?)
      `).run(req.user.id, lessonId, maxWatched, duration, isCompleted);
    }

    res.json({ watched_seconds: maxWatched, duration_seconds: duration, is_completed: !!isCompleted });
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/lessons/:id/progress — получить свой прогресс просмотра (студент)
app.get('/api/lessons/:id/progress', requireAuth('student'), (req, res) => {
  try {
    const lesson = db.prepare('SELECT id, playlist_id FROM lessons WHERE id = ?').get(req.params.id);
    if (!lesson) return res.status(404).json({ error: 'Урок не найден' });
    if (!studentHasPlaylistAccess(req.user.id, lesson.playlist_id))
      return res.status(403).json({ error: 'Нет доступа к этому уроку' });

    const row = db.prepare(`
      SELECT * FROM lesson_progress WHERE student_id = ? AND lesson_id = ?
    `).get(req.user.id, req.params.id);
    res.json(row || { watched_seconds: 0, duration_seconds: 0, is_completed: 0 });
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/homework/lesson/:lesson_id — все сдачи по уроку (только учитель)
app.get('/api/homework/lesson/:lesson_id', requireAuth('teacher', 'admin'), (req, res) => {
  try {
    if (req.user.role === 'teacher') {
      const lesson = db.prepare(`
        SELECT l.id, p.teacher_id as playlist_teacher_id
        FROM lessons l JOIN playlists p ON p.id = l.playlist_id
        WHERE l.id = ?
      `).get(req.params.lesson_id);
      if (!lesson) return res.status(404).json({ error: 'Урок не найден' });
      if (lesson.playlist_teacher_id !== req.user.id)
        return res.status(403).json({ error: 'Нет доступа' });
    }

    const submissions = db.prepare(`
      SELECT hs.*,
             u.full_name  as student_name,
             u.username   as student_username,
             l.title      as lesson_title
      FROM homework_submissions hs
      JOIN users u   ON u.id  = hs.student_id
      JOIN lessons l ON l.id  = hs.lesson_id
      WHERE hs.lesson_id = ?
      ORDER BY hs.submitted_at DESC
    `).all(req.params.lesson_id);

    res.json(submissions);
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/homework/student/:student_id — Д/З одного студента
app.get('/api/homework/student/:student_id', requireAuth('admin', 'teacher', 'student'), (req, res) => {
  try {
    const { student_id } = req.params;

    // Студент может видеть только свои работы
    if (req.user.role === 'student' && req.user.id !== parseInt(student_id))
      return res.status(403).json({ error: 'Нет доступа' });

    const submissions = db.prepare(`
      SELECT hs.*,
             l.title       as lesson_title,
             u.full_name   as student_name
      FROM homework_submissions hs
      JOIN lessons l ON l.id = hs.lesson_id
      JOIN users u   ON u.id = hs.student_id
      WHERE hs.student_id = ?
      ORDER BY hs.submitted_at DESC
    `).all(student_id);

    res.json(submissions);
  } catch (e) {
    sendServerError(res, e);
  }
});

// PUT /api/homework/:id/grade — выставить оценку за Д/З (только учитель)
app.put('/api/homework/:id/grade', requireAuth('teacher'), (req, res) => {
  try {
    const { id }             = req.params;
    const { grade, comment } = req.body;

    if (grade === undefined || grade === null)
      return res.status(400).json({ error: 'Оценка обязательна' });
    if (grade < 0 || grade > 100)
      return res.status(400).json({ error: 'Оценка должна быть от 0 до 100' });

    const submission = db.prepare(`
      SELECT hs.*, p.teacher_id as playlist_teacher_id, l.playlist_id
      FROM homework_submissions hs
      JOIN lessons l    ON l.id = hs.lesson_id
      JOIN playlists p  ON p.id = l.playlist_id
      WHERE hs.id = ?
    `).get(id);
    if (!submission) return res.status(404).json({ error: 'Работа не найдена' });

    // Учитель может оценивать только Д/З по урокам из своих плейлистов
    if (submission.playlist_teacher_id !== req.user.id)
      return res.status(403).json({ error: 'Нет доступа' });

    // Обновляем оценку в homework_submissions — это ручное переопределение учителем
    // (даже если до этого её выставил ИИ)
    db.prepare(`
      UPDATE homework_submissions
      SET grade = ?, comment = ?, graded_at = CURRENT_TIMESTAMP,
          graded_by = 'teacher', teacher_overridden = 1
      WHERE id = ?
    `).run(grade, comment || null, id);

    // Синхронизируем недельную оценку в журнале (100-балльная система)
    upsertWeeklyGradeFromHomework(
      submission.student_id, submission.lesson_id, submission.playlist_id,
      req.user.id, grade, comment || null, 'teacher'
    );

    const updated = db.prepare(`
      SELECT hs.*,
             u.full_name  as student_name,
             l.title      as lesson_title
      FROM homework_submissions hs
      JOIN users u   ON u.id = hs.student_id
      JOIN lessons l ON l.id = hs.lesson_id
      WHERE hs.id = ?
    `).get(id);

    res.json(updated);
  } catch (e) {
    sendServerError(res, e);
  }
});

// ─────────────────────────────────────────────
// API: ЖУРНАЛ ОЦЕНОК
// ─────────────────────────────────────────────

// GET /api/grades/student/:student_id — оценки студента
app.get('/api/grades/student/:student_id', requireAuth('admin', 'teacher', 'student'), (req, res) => {
  try {
    const { student_id } = req.params;

    // Студент видит только свои оценки
    if (req.user.role === 'student' && req.user.id !== parseInt(student_id))
      return res.status(403).json({ error: 'Нет доступа' });

    const grades = db.prepare(`
      SELECT g.*,
             l.title       as lesson_title,
             t.full_name   as teacher_name,
             s.full_name   as student_name
      FROM grades g
      LEFT JOIN lessons l ON l.id = g.lesson_id
      LEFT JOIN users t   ON t.id = g.teacher_id
      JOIN users s        ON s.id = g.student_id
      WHERE g.student_id = ?
      ORDER BY g.created_at DESC
    `).all(student_id);

    res.json(grades);
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/grades — выставить оценку вручную (только учитель)
app.post('/api/grades', requireAuth('teacher'), (req, res) => {
  try {
    const { student_id, value, comment, lesson_id } = req.body;

    if (!student_id || value === undefined || value === null)
      return res.status(400).json({ error: 'student_id и value обязательны' });
    if (!Number.isInteger(value) || value < 0 || value > 100)
      return res.status(400).json({ error: 'Оценка должна быть целым числом от 0 до 100' });

    const student = db.prepare(
      "SELECT id FROM users WHERE id = ? AND role = 'student'"
    ).get(student_id);
    if (!student) return res.status(404).json({ error: 'Студент не найден' });

    let playlistId = null, groupId = null;
    if (lesson_id) {
      const lesson = db.prepare(`
        SELECT l.playlist_id, p.teacher_id as playlist_teacher_id
        FROM lessons l JOIN playlists p ON p.id = l.playlist_id
        WHERE l.id = ?
      `).get(lesson_id);
      if (!lesson) return res.status(404).json({ error: 'Урок не найден' });
      if (lesson.playlist_teacher_id !== req.user.id)
        return res.status(403).json({ error: 'Нет доступа к этому уроку' });

      playlistId = lesson.playlist_id;
      groupId = resolveGroupForStudentPlaylist(student_id, playlistId);
      if (!groupId)
        return res.status(403).json({ error: 'Этот студент не изучает данный курс в вашей группе' });
    } else if (!teacherTeachesStudent(req.user.id, student_id)) {
      // Оценка без привязки к уроку — всё равно должна ставиться только своему студенту
      return res.status(403).json({ error: 'Вы не ведёте этого студента ни в одной группе' });
    }

    const result = db.prepare(`
      INSERT INTO grades (student_id, teacher_id, lesson_id, playlist_id, group_id, control_type, value, max_value, comment, graded_by)
      VALUES (?, ?, ?, ?, ?, 'weekly', ?, 100, ?, 'teacher')
    `).run(student_id, req.user.id, lesson_id || null, playlistId, groupId, value, comment || null);

    const grade = db.prepare(`
      SELECT g.*,
             l.title      as lesson_title,
             t.full_name  as teacher_name,
             s.full_name  as student_name
      FROM grades g
      LEFT JOIN lessons l ON l.id = g.lesson_id
      LEFT JOIN users t   ON t.id = g.teacher_id
      JOIN users s        ON s.id = g.student_id
      WHERE g.id = ?
    `).get(result.lastInsertRowid);

    createGradeNotification(grade, false);

    res.status(201).json(grade);
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/grades — все оценки (только admin и teacher)
app.get('/api/grades', requireAuth('admin', 'teacher'), (req, res) => {
  try {
    let grades;
    if (req.user.role === 'teacher') {
      grades = db.prepare(`
        SELECT g.*,
               l.title      as lesson_title,
               t.full_name  as teacher_name,
               s.full_name  as student_name
        FROM grades g
        LEFT JOIN lessons l ON l.id = g.lesson_id
        LEFT JOIN users t   ON t.id = g.teacher_id
        JOIN users s        ON s.id = g.student_id
        WHERE g.teacher_id = ?
        ORDER BY g.created_at DESC
      `).all(req.user.id);
    } else {
      grades = db.prepare(`
        SELECT g.*,
               l.title      as lesson_title,
               t.full_name  as teacher_name,
               s.full_name  as student_name
        FROM grades g
        LEFT JOIN lessons l ON l.id = g.lesson_id
        LEFT JOIN users t   ON t.id = g.teacher_id
        JOIN users s        ON s.id = g.student_id
        ORDER BY g.created_at DESC
      `).all();
    }
    res.json(grades);
  } catch (e) {
    sendServerError(res, e);
  }
});

// PUT /api/grades/:id — редактировать уже выставленную оценку (учитель/админ)
app.put('/api/grades/:id', requireAuth('teacher', 'admin'), (req, res) => {
  try {
    const { id } = req.params;
    const { value, comment } = req.body;
    if (value === undefined || value === null || !Number.isInteger(value) || value < 0 || value > 100)
      return res.status(400).json({ error: 'Оценка должна быть целым числом от 0 до 100' });

    const grade = db.prepare('SELECT * FROM grades WHERE id = ?').get(id);
    if (!grade) return res.status(404).json({ error: 'Оценка не найдена' });
    if (req.user.role === 'teacher' && grade.teacher_id !== req.user.id)
      return res.status(403).json({ error: 'Нет доступа' });

    const original = grade.original_value !== null && grade.original_value !== undefined
      ? grade.original_value : grade.value;

    db.prepare(`
      UPDATE grades
      SET value = ?, comment = ?, original_value = ?, edited_by = ?, edited_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(value, comment ?? grade.comment, original, req.user.id, id);

    // Если это оценка за ДЗ (привязана к уроку) — синхронизируем homework_submissions
    if (grade.lesson_id && grade.control_type === 'weekly') {
      db.prepare(`
        UPDATE homework_submissions
        SET grade = ?, graded_by = 'teacher', teacher_overridden = 1
        WHERE student_id = ? AND lesson_id = ?
      `).run(value, grade.student_id, grade.lesson_id);
    }

    const updatedGrade = db.prepare('SELECT * FROM grades WHERE id = ?').get(id);
    createGradeNotification(updatedGrade, true);

    res.json(updatedGrade);
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/grades/checkpoint — выставить рубежный контроль (учитель)
// control_type: 'checkpoint1' | 'checkpoint2'
app.post('/api/grades/checkpoint', requireAuth('teacher'), (req, res) => {
  try {
    const { student_id, playlist_id, control_type, value, comment } = req.body;
    if (!student_id || !playlist_id || !control_type || value === undefined)
      return res.status(400).json({ error: 'student_id, playlist_id, control_type, value обязательны' });
    if (!['checkpoint1', 'checkpoint2'].includes(control_type))
      return res.status(400).json({ error: 'control_type должен быть checkpoint1 или checkpoint2' });
    if (!Number.isInteger(value) || value < 0 || value > 100)
      return res.status(400).json({ error: 'Оценка должна быть целым числом от 0 до 100' });

    const playlist = db.prepare('SELECT * FROM playlists WHERE id = ? AND teacher_id = ?').get(playlist_id, req.user.id);
    if (!playlist) return res.status(403).json({ error: 'Нет доступа к этому плейлисту' });

    // Правило: без недельных оценок по всем урокам — нельзя выставить рубежку
    if (!weeklyComplete(student_id, playlist_id))
      return res.status(400).json({ error: 'Сначала должны быть выставлены все недельные оценки по урокам этого курса' });

    // Рубежка 2 требует, чтобы рубежка 1 уже была выставлена
    if (control_type === 'checkpoint2' && !getControlGrade(student_id, playlist_id, 'checkpoint1'))
      return res.status(400).json({ error: 'Сначала выставьте рубежный контроль 1' });

    // Если для этого этапа настроен экзамен — студент должен его сдать
    const exam = getStageExam(playlist_id, control_type);
    if (exam && !studentPassedExam(student_id, exam.id))
      return res.status(400).json({ error: `Студент ещё не сдал экзамен "${exam.title}" для этого этапа` });

    const groupId = resolveGroupForStudentPlaylist(student_id, playlist_id);
    const existing = getControlGrade(student_id, playlist_id, control_type);

    let gradeRow;
    if (existing) {
      const original = existing.original_value !== null ? existing.original_value : existing.value;
      db.prepare(`
        UPDATE grades SET value = ?, comment = ?, original_value = ?, edited_by = ?, edited_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(value, comment || null, original, req.user.id, existing.id);
      gradeRow = db.prepare('SELECT * FROM grades WHERE id = ?').get(existing.id);
      createGradeNotification(gradeRow, true);
    } else {
      const result = db.prepare(`
        INSERT INTO grades (student_id, teacher_id, playlist_id, group_id, control_type, value, max_value, comment, graded_by)
        VALUES (?, ?, ?, ?, ?, ?, 100, ?, 'teacher')
      `).run(student_id, req.user.id, playlist_id, groupId, control_type, value, comment || null);
      gradeRow = db.prepare('SELECT * FROM grades WHERE id = ?').get(result.lastInsertRowid);
      createGradeNotification(gradeRow, false);
    }

    let sessionGrade = null;
    if (control_type === 'checkpoint2') {
      sessionGrade = maybeCreateSessionGrade(student_id, playlist_id);
    }

    res.json({ grade: gradeRow, session_grade: sessionGrade });
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/grades/journal — 100-балльный журнал по группе и курсу (учитель/оператор/админ)
app.get('/api/grades/journal', requireAuth('teacher', 'operator', 'admin'), (req, res) => {
  try {
    const { group_id, playlist_id } = req.query;
    if (!group_id || !playlist_id)
      return res.status(400).json({ error: 'group_id и playlist_id обязательны' });

    if (req.user.role === 'teacher') {
      const playlist = db.prepare('SELECT id FROM playlists WHERE id = ? AND teacher_id = ?').get(playlist_id, req.user.id);
      if (!playlist) return res.status(403).json({ error: 'Нет доступа к этому курсу' });
    }

    const students = db.prepare(`
      SELECT u.id, u.full_name, u.username
      FROM group_students gs
      JOIN users u ON u.id = gs.student_id
      WHERE gs.group_id = ?
      ORDER BY u.full_name ASC
    `).all(group_id);

    const lessons = db.prepare(`
      SELECT id, title, order_index, deadline FROM lessons WHERE playlist_id = ? ORDER BY order_index ASC
    `).all(playlist_id);

    const allGrades = db.prepare(`
      SELECT * FROM grades WHERE playlist_id = ? AND group_id = ?
    `).all(playlist_id, group_id);

    const exams = {
      checkpoint1: getStageExam(playlist_id, 'checkpoint1'),
      checkpoint2: getStageExam(playlist_id, 'checkpoint2'),
      session: getStageExam(playlist_id, 'session')
    };

    const journal = students.map(st => {
      const weekly = {};
      lessons.forEach(l => {
        const g = allGrades.find(g => g.student_id === st.id && g.lesson_id === l.id && g.control_type === 'weekly');
        const access = l.deadline ? getLessonAccessStatus(l, st.id) : null;
        weekly[l.id] = {
          grade: g ? { value: g.value, graded_by: g.graded_by, edited_by: g.edited_by, id: g.id } : null,
          attendance: access ? access.status : 'no_deadline' // 'no_deadline' | 'in_progress' | 'completed' | 'absence' | 'reopened'
        };
      });
      const cp1 = allGrades.find(g => g.student_id === st.id && g.control_type === 'checkpoint1');
      const cp2 = allGrades.find(g => g.student_id === st.id && g.control_type === 'checkpoint2');
      const session = allGrades.find(g => g.student_id === st.id && g.control_type === 'session');
      return {
        student: st,
        weekly,
        checkpoint1: cp1 ? { value: cp1.value, id: cp1.id, edited_by: cp1.edited_by } : null,
        checkpoint2: cp2 ? { value: cp2.value, id: cp2.id, edited_by: cp2.edited_by } : null,
        session: session ? { value: session.value, id: session.id, graded_by: session.graded_by } : null,
        weekly_complete: weeklyComplete(st.id, playlist_id)
      };
    });

    res.json({ lessons, exams, journal });
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/grades/journal/export — экспорт ведомости в Excel (.xlsx)
app.get('/api/grades/journal/export', requireAuth('teacher', 'operator', 'admin'), (req, res) => {
  try {
    const { group_id, playlist_id } = req.query;
    if (!group_id || !playlist_id)
      return res.status(400).json({ error: 'group_id и playlist_id обязательны' });

    if (req.user.role === 'teacher') {
      const owns = db.prepare('SELECT id FROM playlists WHERE id = ? AND teacher_id = ?').get(playlist_id, req.user.id);
      if (!owns) return res.status(403).json({ error: 'Нет доступа к этому курсу' });
    }

    const group    = db.prepare('SELECT * FROM groups WHERE id = ?').get(group_id);
    const playlist = db.prepare('SELECT * FROM playlists WHERE id = ?').get(playlist_id);
    if (!group || !playlist) return res.status(404).json({ error: 'Группа или курс не найдены' });

    const students = db.prepare(`
      SELECT u.id, u.full_name, u.username FROM group_students gs
      JOIN users u ON u.id = gs.student_id
      WHERE gs.group_id = ?
      ORDER BY u.full_name ASC
    `).all(group_id);

    const lessons = db.prepare(`
      SELECT id, title, order_index, deadline FROM lessons WHERE playlist_id = ? ORDER BY order_index ASC
    `).all(playlist_id);

    const allGrades = db.prepare(`
      SELECT * FROM grades WHERE playlist_id = ? AND group_id = ?
    `).all(playlist_id, group_id);

    const header = ['№', 'ФИО', 'Логин', ...lessons.map((l, i) => `Урок ${i + 1}`), 'Рубежка 1', 'Рубежка 2', 'Сессия', 'Пропуски'];
    const rows = [header];

    students.forEach((st, idx) => {
      const row = [idx + 1, st.full_name || st.username, st.username];
      let absences = 0;
      lessons.forEach(l => {
        const g = allGrades.find(g => g.student_id === st.id && g.lesson_id === l.id && g.control_type === 'weekly');
        const access = l.deadline ? getLessonAccessStatus(l, st.id) : null;
        if (access && access.status === 'absence') { absences++; row.push('Н/Б'); }
        else row.push(g ? g.value : '');
      });
      const cp1 = allGrades.find(g => g.student_id === st.id && g.control_type === 'checkpoint1');
      const cp2 = allGrades.find(g => g.student_id === st.id && g.control_type === 'checkpoint2');
      const session = allGrades.find(g => g.student_id === st.id && g.control_type === 'session');
      row.push(cp1 ? cp1.value : '', cp2 ? cp2.value : '', session ? session.value : '', absences);
      rows.push(row);
    });

    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.aoa_to_sheet(rows);
    ws['!cols'] = [{ wch: 4 }, { wch: 28 }, { wch: 16 }, ...lessons.map(() => ({ wch: 10 })), { wch: 10 }, { wch: 10 }, { wch: 10 }, { wch: 10 }];
    XLSX.utils.book_append_sheet(wb, ws, 'Ведомость');

    const fileName = `Ведомость_${group.name}_${playlist.title}.xlsx`.replace(/[\\/:*?"<>|]/g, '_');
    const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    logAudit(req.user, 'export_journal', 'playlist', parseInt(playlist_id), { group_id: parseInt(group_id) });

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fileName)}"`);
    res.send(buf);
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/grades/my-report/:playlist_id — разбивка оценок студента по курсу (студент)
app.get('/api/grades/my-report/:playlist_id', requireAuth('student'), (req, res) => {
  try {
    const playlistId = req.params.playlist_id;
    const lessons = db.prepare(`
      SELECT id, title, order_index FROM lessons WHERE playlist_id = ? ORDER BY order_index ASC
    `).all(playlistId);

    const grades = db.prepare(`
      SELECT * FROM grades WHERE student_id = ? AND playlist_id = ?
    `).all(req.user.id, playlistId);

    const weekly = lessons.map(l => {
      const g = grades.find(g => g.lesson_id === l.id && g.control_type === 'weekly');
      return { lesson_id: l.id, lesson_title: l.title, value: g ? g.value : null };
    });
    const checkpoint1 = grades.find(g => g.control_type === 'checkpoint1') || null;
    const checkpoint2 = grades.find(g => g.control_type === 'checkpoint2') || null;
    const session = grades.find(g => g.control_type === 'session') || null;

    res.json({
      weekly, checkpoint1, checkpoint2, session,
      weekly_complete: weeklyComplete(req.user.id, playlistId)
    });
  } catch (e) {
    sendServerError(res, e);
  }
});

// ─────────────────────────────────────────────
// API: ФАКУЛЬТЕТЫ (оператор/админ)
// ─────────────────────────────────────────────
app.get('/api/faculties', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    const faculties = db.prepare(`
      SELECT f.*, (SELECT COUNT(*) FROM groups g WHERE g.faculty_id = f.id) as group_count
      FROM faculties f ORDER BY f.name ASC
    `).all();
    res.json(faculties);
  } catch (e) { sendServerError(res, e); }
});

app.post('/api/faculties', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: 'Название обязательно' });
    const result = db.prepare('INSERT INTO faculties (name, description) VALUES (?, ?)').run(name, description || '');
    res.status(201).json(db.prepare('SELECT * FROM faculties WHERE id = ?').get(result.lastInsertRowid));
  } catch (e) { sendServerError(res, e); }
});

app.put('/api/faculties/:id', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const { name, description } = req.body;
    const f = db.prepare('SELECT id FROM faculties WHERE id = ?').get(req.params.id);
    if (!f) return res.status(404).json({ error: 'Факультет не найден' });
    db.prepare('UPDATE faculties SET name = ?, description = ? WHERE id = ?')
      .run(name, description || '', req.params.id);
    res.json(db.prepare('SELECT * FROM faculties WHERE id = ?').get(req.params.id));
  } catch (e) { sendServerError(res, e); }
});

app.delete('/api/faculties/:id', requireAuth('admin', 'operator'), (req, res) => {
  try {
    db.prepare('DELETE FROM faculties WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  } catch (e) { sendServerError(res, e); }
});

// ─────────────────────────────────────────────
// API: КАФЕДРЫ (внутри факультета)
// ─────────────────────────────────────────────
app.get('/api/departments', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    const { faculty_id } = req.query;
    let sql = `
      SELECT d.*, f.name as faculty_name,
             (SELECT COUNT(*) FROM specialties s WHERE s.department_id = d.id) as specialty_count
      FROM departments d JOIN faculties f ON f.id = d.faculty_id
    `;
    const params = [];
    if (faculty_id) { sql += ' WHERE d.faculty_id = ?'; params.push(faculty_id); }
    sql += ' ORDER BY d.name ASC';
    res.json(db.prepare(sql).all(...params));
  } catch (e) { sendServerError(res, e); }
});

app.post('/api/departments', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const { name, description, faculty_id } = req.body;
    if (!name || !faculty_id) return res.status(400).json({ error: 'name и faculty_id обязательны' });
    const fac = db.prepare('SELECT id FROM faculties WHERE id = ?').get(faculty_id);
    if (!fac) return res.status(404).json({ error: 'Факультет не найден' });
    const result = db.prepare('INSERT INTO departments (name, description, faculty_id) VALUES (?, ?, ?)')
      .run(name, description || '', faculty_id);
    res.status(201).json(db.prepare('SELECT * FROM departments WHERE id = ?').get(result.lastInsertRowid));
  } catch (e) { sendServerError(res, e); }
});

app.put('/api/departments/:id', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const { name, description, faculty_id } = req.body;
    const d = db.prepare('SELECT id FROM departments WHERE id = ?').get(req.params.id);
    if (!d) return res.status(404).json({ error: 'Кафедра не найдена' });
    db.prepare('UPDATE departments SET name = ?, description = ?, faculty_id = ? WHERE id = ?')
      .run(name, description || '', faculty_id, req.params.id);
    res.json(db.prepare('SELECT * FROM departments WHERE id = ?').get(req.params.id));
  } catch (e) { sendServerError(res, e); }
});

app.delete('/api/departments/:id', requireAuth('admin', 'operator'), (req, res) => {
  try {
    db.prepare('DELETE FROM departments WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  } catch (e) { sendServerError(res, e); }
});

// ─────────────────────────────────────────────
// API: СПЕЦИАЛЬНОСТИ (внутри кафедры)
// ─────────────────────────────────────────────
app.get('/api/specialties', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    const { department_id } = req.query;
    let sql = `
      SELECT s.*, d.name as department_name, d.faculty_id,
             (SELECT COUNT(*) FROM groups g WHERE g.specialty_id = s.id) as group_count
      FROM specialties s JOIN departments d ON d.id = s.department_id
    `;
    const params = [];
    if (department_id) { sql += ' WHERE s.department_id = ?'; params.push(department_id); }
    sql += ' ORDER BY s.name ASC';
    res.json(db.prepare(sql).all(...params));
  } catch (e) { sendServerError(res, e); }
});

app.post('/api/specialties', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const { name, description, department_id } = req.body;
    if (!name || !department_id) return res.status(400).json({ error: 'name и department_id обязательны' });
    const dep = db.prepare('SELECT id FROM departments WHERE id = ?').get(department_id);
    if (!dep) return res.status(404).json({ error: 'Кафедра не найдена' });
    const result = db.prepare('INSERT INTO specialties (name, description, department_id) VALUES (?, ?, ?)')
      .run(name, description || '', department_id);
    res.status(201).json(db.prepare('SELECT * FROM specialties WHERE id = ?').get(result.lastInsertRowid));
  } catch (e) { sendServerError(res, e); }
});

app.put('/api/specialties/:id', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const { name, description, department_id } = req.body;
    const s = db.prepare('SELECT id FROM specialties WHERE id = ?').get(req.params.id);
    if (!s) return res.status(404).json({ error: 'Специальность не найдена' });
    db.prepare('UPDATE specialties SET name = ?, description = ?, department_id = ? WHERE id = ?')
      .run(name, description || '', department_id, req.params.id);
    res.json(db.prepare('SELECT * FROM specialties WHERE id = ?').get(req.params.id));
  } catch (e) { sendServerError(res, e); }
});

app.delete('/api/specialties/:id', requireAuth('admin', 'operator'), (req, res) => {
  try {
    db.prepare('DELETE FROM specialties WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  } catch (e) { sendServerError(res, e); }
});

// ─────────────────────────────────────────────
// API: ГРУППЫ (оператор создаёт, назначает куратора и учителей)
// ─────────────────────────────────────────────
app.get('/api/groups', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    let groups;
    if (req.user.role === 'student') {
      groups = db.prepare(`
        SELECT g.*, f.name as faculty_name, u.full_name as curator_name
        FROM groups g
        JOIN group_students gs ON gs.group_id = g.id
        JOIN faculties f ON f.id = g.faculty_id
        LEFT JOIN users u ON u.id = g.curator_id
        WHERE gs.student_id = ?
      `).all(req.user.id);
    } else if (req.user.role === 'teacher') {
      groups = db.prepare(`
        SELECT DISTINCT g.*, f.name as faculty_name, u.full_name as curator_name
        FROM groups g
        JOIN faculties f ON f.id = g.faculty_id
        LEFT JOIN users u ON u.id = g.curator_id
        LEFT JOIN group_teachers gt ON gt.group_id = g.id
        WHERE g.curator_id = ? OR gt.teacher_id = ?
      `).all(req.user.id, req.user.id);
    } else {
      groups = db.prepare(`
        SELECT g.*, f.name as faculty_name, u.full_name as curator_name,
               (SELECT COUNT(*) FROM group_students gs WHERE gs.group_id = g.id) as student_count
        FROM groups g
        JOIN faculties f ON f.id = g.faculty_id
        LEFT JOIN users u ON u.id = g.curator_id
        ORDER BY g.created_at DESC
      `).all();
    }
    res.json(groups);
  } catch (e) { sendServerError(res, e); }
});

app.get('/api/groups/:id', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    const group = db.prepare(`
      SELECT g.*, f.name as faculty_name, u.full_name as curator_name
      FROM groups g
      JOIN faculties f ON f.id = g.faculty_id
      LEFT JOIN users u ON u.id = g.curator_id
      WHERE g.id = ?
    `).get(req.params.id);
    if (!group) return res.status(404).json({ error: 'Группа не найдена' });

    if (req.user.role === 'student') {
      const inGroup = db.prepare('SELECT 1 FROM group_students WHERE group_id = ? AND student_id = ?').get(req.params.id, req.user.id);
      if (!inGroup) return res.status(403).json({ error: 'Нет доступа' });
    }
    if (req.user.role === 'teacher' && !teacherHasGroupAccess(req.user.id, req.params.id)) {
      return res.status(403).json({ error: 'Нет доступа' });
    }

    group.students = db.prepare(`
      SELECT u.id, u.full_name, u.username FROM group_students gs
      JOIN users u ON u.id = gs.student_id WHERE gs.group_id = ?
      ORDER BY u.full_name ASC
    `).all(req.params.id);

    group.teachers = db.prepare(`
      SELECT gt.id as assignment_id, u.id as teacher_id, u.full_name as teacher_name,
             p.id as playlist_id, p.title as playlist_title
      FROM group_teachers gt
      JOIN users u ON u.id = gt.teacher_id
      JOIN playlists p ON p.id = gt.playlist_id
      WHERE gt.group_id = ?
    `).all(req.params.id);

    res.json(group);
  } catch (e) { sendServerError(res, e); }
});

// Выводит department_id/faculty_id по specialty_id (специальность → кафедра → факультет)
function resolveOrgChainBySpecialty(specialtyId) {
  const row = db.prepare(`
    SELECT s.id as specialty_id, d.id as department_id, f.id as faculty_id
    FROM specialties s
    JOIN departments d ON d.id = s.department_id
    JOIN faculties f ON f.id = d.faculty_id
    WHERE s.id = ?
  `).get(specialtyId);
  return row || null;
}

app.post('/api/groups', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const { name, faculty_id, curator_id, specialty_id, course } = req.body;
    if (!name) return res.status(400).json({ error: 'name обязателен' });
    if (curator_id) {
      const t = db.prepare("SELECT id FROM users WHERE id = ? AND role = 'teacher'").get(curator_id);
      if (!t) return res.status(400).json({ error: 'Куратор должен быть учителем' });
    }

    let finalFacultyId = faculty_id || null;
    let finalDeptId = null;
    let finalSpecId = specialty_id || null;

    if (specialty_id) {
      const chain = resolveOrgChainBySpecialty(specialty_id);
      if (!chain) return res.status(404).json({ error: 'Специальность не найдена' });
      finalDeptId = chain.department_id;
      finalFacultyId = chain.faculty_id;
    }
    if (!finalFacultyId) return res.status(400).json({ error: 'Укажите либо faculty_id, либо specialty_id' });
    if (course !== undefined && course !== null && course !== '' && (course < 1 || course > 6)) {
      return res.status(400).json({ error: 'Курс должен быть от 1 до 6' });
    }

    const result = db.prepare(`
      INSERT INTO groups (name, faculty_id, curator_id, department_id, specialty_id, course)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(name, finalFacultyId, curator_id || null, finalDeptId, finalSpecId, course || null);
    res.status(201).json(db.prepare('SELECT * FROM groups WHERE id = ?').get(result.lastInsertRowid));
  } catch (e) { sendServerError(res, e); }
});

app.put('/api/groups/:id', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const { name, faculty_id, curator_id, specialty_id, course } = req.body;
    const g = db.prepare('SELECT id FROM groups WHERE id = ?').get(req.params.id);
    if (!g) return res.status(404).json({ error: 'Группа не найдена' });
    if (curator_id) {
      const t = db.prepare("SELECT id FROM users WHERE id = ? AND role = 'teacher'").get(curator_id);
      if (!t) return res.status(400).json({ error: 'Куратор должен быть учителем' });
    }

    let finalFacultyId = faculty_id || null;
    let finalDeptId = null;
    let finalSpecId = specialty_id || null;

    if (specialty_id) {
      const chain = resolveOrgChainBySpecialty(specialty_id);
      if (!chain) return res.status(404).json({ error: 'Специальность не найдена' });
      finalDeptId = chain.department_id;
      finalFacultyId = chain.faculty_id;
    }
    if (!finalFacultyId) return res.status(400).json({ error: 'Укажите либо faculty_id, либо specialty_id' });
    if (course !== undefined && course !== null && course !== '' && (course < 1 || course > 6)) {
      return res.status(400).json({ error: 'Курс должен быть от 1 до 6' });
    }

    db.prepare(`
      UPDATE groups SET name = ?, faculty_id = ?, curator_id = ?, department_id = ?, specialty_id = ?, course = ?
      WHERE id = ?
    `).run(name, finalFacultyId, curator_id || null, finalDeptId, finalSpecId, course || null, req.params.id);
    res.json(db.prepare('SELECT * FROM groups WHERE id = ?').get(req.params.id));
  } catch (e) { sendServerError(res, e); }
});

app.delete('/api/groups/:id', requireAuth('admin', 'operator'), (req, res) => {
  try {
    db.prepare('DELETE FROM groups WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  } catch (e) { sendServerError(res, e); }
});

// GET /api/groups/:id/performance — сводная успеваемость группы в процентах
// (по всем курсам, закреплённым за группой): средний балл, % пройденных
// уроков в срок, % посещаемости. Доступно учителю (только по своим курсам
// в этой группе), оператору и админу (по всем курсам группы).
function computeGroupPerformance(groupId, teacherFilterId) {
    const group = db.prepare('SELECT * FROM groups WHERE id = ?').get(groupId);
    if (!group) return { error: 'Группа не найдена', status: 404 };

    let assignments = db.prepare(`
      SELECT DISTINCT gt.playlist_id, gt.teacher_id, p.title as playlist_title, u.full_name as teacher_name
      FROM group_teachers gt
      JOIN playlists p ON p.id = gt.playlist_id
      JOIN users u ON u.id = gt.teacher_id
      WHERE gt.group_id = ?
    `).all(groupId);

    if (teacherFilterId) {
      assignments = assignments.filter(a => a.teacher_id === teacherFilterId);
      if (!assignments.length) return { error: 'У вас нет курсов в этой группе', status: 403 };
    }

    const students = db.prepare(`
      SELECT u.id, u.full_name, u.username
      FROM group_students gs JOIN users u ON u.id = gs.student_id
      WHERE gs.group_id = ? ORDER BY u.full_name ASC
    `).all(groupId);

    const courses = assignments.map(a => {
      const lessons = db.prepare('SELECT id, title, deadline FROM lessons WHERE playlist_id = ? ORDER BY order_index ASC').all(a.playlist_id);
      const allGrades = db.prepare('SELECT * FROM grades WHERE playlist_id = ? AND group_id = ?').all(a.playlist_id, groupId);
      const lessonsWithDeadline = lessons.filter(l => l.deadline);

      const perStudent = students.map(st => {
        let sumPct = 0, cntGraded = 0;
        let attended = 0, missed = 0, pending = 0;

        lessons.forEach(l => {
          const g = allGrades.find(g => g.student_id === st.id && g.lesson_id === l.id && g.control_type === 'weekly');
          if (g) { sumPct += (g.value / (g.max_value || 100)) * 100; cntGraded++; }
          if (l.deadline) {
            const access = getLessonAccessStatus(l, st.id);
            if (access.status === 'absence') missed++;
            else if (access.status === 'in_progress') pending++;
            else attended++; // completed / reopened
          }
        });

        ['checkpoint1', 'checkpoint2', 'session'].forEach(ct => {
          const g = allGrades.find(g => g.student_id === st.id && g.control_type === ct);
          if (g) { sumPct += (g.value / (g.max_value || 100)) * 100; cntGraded++; }
        });

        const avgPct = cntGraded ? Math.round(sumPct / cntGraded) : null;
        const attendanceTotal = lessonsWithDeadline.length;
        const attendancePct = attendanceTotal ? Math.round((attended / attendanceTotal) * 100) : null;

        return {
          student_id: st.id,
          avg_grade_pct: avgPct,
          attendance_pct: attendancePct,
          lessons_total: lessons.length,
          lessons_graded: cntGraded,
          missed_deadlines: missed,
          pending_deadlines: pending
        };
      });

      const withGrade = perStudent.filter(s => s.avg_grade_pct !== null);
      const withAttendance = perStudent.filter(s => s.attendance_pct !== null);
      const courseAvgGrade = withGrade.length ? Math.round(withGrade.reduce((s, x) => s + x.avg_grade_pct, 0) / withGrade.length) : null;
      const courseAvgAttendance = withAttendance.length ? Math.round(withAttendance.reduce((s, x) => s + x.attendance_pct, 0) / withAttendance.length) : null;

      return {
        playlist_id: a.playlist_id,
        playlist_title: a.playlist_title,
        teacher_name: a.teacher_name,
        lessons_total: lessons.length,
        avg_grade_pct: courseAvgGrade,
        avg_attendance_pct: courseAvgAttendance,
        students: perStudent
      };
    });

    const studentSummary = students.map(st => {
      const rows = courses.map(c => c.students.find(s => s.student_id === st.id)).filter(Boolean);
      const withGrade = rows.filter(r => r.avg_grade_pct !== null);
      const withAtt = rows.filter(r => r.attendance_pct !== null);
      return {
        student: st,
        overall_grade_pct: withGrade.length ? Math.round(withGrade.reduce((s, x) => s + x.avg_grade_pct, 0) / withGrade.length) : null,
        overall_attendance_pct: withAtt.length ? Math.round(withAtt.reduce((s, x) => s + x.attendance_pct, 0) / withAtt.length) : null,
        missed_deadlines_total: rows.reduce((s, x) => s + (x.missed_deadlines || 0), 0)
      };
    });

    const gVals = studentSummary.filter(s => s.overall_grade_pct !== null).map(s => s.overall_grade_pct);
    const aVals = studentSummary.filter(s => s.overall_attendance_pct !== null).map(s => s.overall_attendance_pct);

    return {
      group: { id: group.id, name: group.name },
      courses,
      student_summary: studentSummary,
      group_avg_grade_pct: gVals.length ? Math.round(gVals.reduce((a, b) => a + b, 0) / gVals.length) : null,
      group_avg_attendance_pct: aVals.length ? Math.round(aVals.reduce((a, b) => a + b, 0) / aVals.length) : null,
      students_count: students.length,
      courses_count: courses.length
    };
}

app.get('/api/groups/:id/performance', requireAuth('teacher', 'operator', 'admin'), (req, res) => {
  try {
    const teacherFilterId = req.user.role === 'teacher' ? req.user.id : null;
    const result = computeGroupPerformance(req.params.id, teacherFilterId);
    if (result.error) return res.status(result.status || 500).json({ error: result.error });
    res.json(result);
  } catch (e) {
    sendServerError(res, e);
  }
});

// ════════════════════════════════════════════
// ОРГСТРУКТУРА: Факультет → Кафедра → Специальность → Группа (курс = год)
// Взвешенная (по числу студентов) агрегация успеваемости снизу вверх.
// ════════════════════════════════════════════

// Взвешенное среднее значений value[] с весами weight[], пропуская записи
// без данных (null) — они не искажают среднее и не учитываются в весе.
function weightedAvg(items, valueKey, weightKey) {
  const valid = items.filter(i => i[valueKey] !== null && i[valueKey] !== undefined && (i[weightKey] || 0) > 0);
  if (!valid.length) return null;
  const totalWeight = valid.reduce((s, i) => s + i[weightKey], 0);
  if (!totalWeight) return null;
  return Math.round(valid.reduce((s, i) => s + i[valueKey] * i[weightKey], 0) / totalWeight);
}

// Строит полное дерево оргструктуры с посчитанной успеваемостью на каждом
// уровне (взвешено по числу студентов) + сквозной срез по курсам (1-6) +
// итог по всей организации. Используется и для дерева-навигатора, и для
// ИИ-анализа проблемных зон.
function buildOrgTree() {
  const faculties   = db.prepare('SELECT * FROM faculties ORDER BY name ASC').all();
  const departments = db.prepare('SELECT * FROM departments ORDER BY name ASC').all();
  const specialties = db.prepare('SELECT * FROM specialties ORDER BY name ASC').all();
  const allGroups    = db.prepare('SELECT * FROM groups ORDER BY course ASC, name ASC').all();

  const assignedGroups = allGroups.filter(g => g.specialty_id);
  const unassignedGroups = allGroups.filter(g => !g.specialty_id);

  const groupNodes = assignedGroups.map(g => {
    const perf = computeGroupPerformance(g.id, null);
    return {
      id: g.id, name: g.name, course: g.course, specialty_id: g.specialty_id,
      students_count:    perf.students_count || 0,
      avg_grade_pct:      perf.error ? null : perf.group_avg_grade_pct,
      avg_attendance_pct: perf.error ? null : perf.group_avg_attendance_pct,
      courses_count:      perf.error ? 0 : perf.courses_count
    };
  });

  const specialtyNodes = specialties.map(sp => {
    const kids = groupNodes.filter(g => g.specialty_id === sp.id);
    return {
      id: sp.id, name: sp.name, department_id: sp.department_id,
      groups: kids,
      students_count:     kids.reduce((s, g) => s + g.students_count, 0),
      avg_grade_pct:      weightedAvg(kids, 'avg_grade_pct', 'students_count'),
      avg_attendance_pct: weightedAvg(kids, 'avg_attendance_pct', 'students_count')
    };
  });

  const departmentNodes = departments.map(d => {
    const kids = specialtyNodes.filter(sp => sp.department_id === d.id);
    return {
      id: d.id, name: d.name, faculty_id: d.faculty_id,
      specialties: kids,
      students_count:     kids.reduce((s, x) => s + x.students_count, 0),
      avg_grade_pct:      weightedAvg(kids, 'avg_grade_pct', 'students_count'),
      avg_attendance_pct: weightedAvg(kids, 'avg_attendance_pct', 'students_count')
    };
  });

  const facultyNodes = faculties.map(f => {
    const kids = departmentNodes.filter(d => d.faculty_id === f.id);
    return {
      id: f.id, name: f.name,
      departments: kids,
      students_count:     kids.reduce((s, x) => s + x.students_count, 0),
      avg_grade_pct:      weightedAvg(kids, 'avg_grade_pct', 'students_count'),
      avg_attendance_pct: weightedAvg(kids, 'avg_attendance_pct', 'students_count')
    };
  });

  const totals = {
    students_count:     facultyNodes.reduce((s, x) => s + x.students_count, 0),
    avg_grade_pct:      weightedAvg(facultyNodes, 'avg_grade_pct', 'students_count'),
    avg_attendance_pct: weightedAvg(facultyNodes, 'avg_attendance_pct', 'students_count')
  };

  // Сквозной срез по курсам (1-6) — через всю организацию, а не по одному узлу
  const byCourse = {};
  groupNodes.forEach(g => { if (g.course) (byCourse[g.course] = byCourse[g.course] || []).push(g); });
  const courseBreakdown = Object.keys(byCourse).map(Number).sort((a, b) => a - b).map(c => {
    const kids = byCourse[c];
    return {
      course: c,
      groups_count:        kids.length,
      students_count:      kids.reduce((s, g) => s + g.students_count, 0),
      avg_grade_pct:        weightedAvg(kids, 'avg_grade_pct', 'students_count'),
      avg_attendance_pct:   weightedAvg(kids, 'avg_attendance_pct', 'students_count')
    };
  });

  return {
    faculties: facultyNodes,
    totals,
    course_breakdown: courseBreakdown,
    unassigned_groups: unassignedGroups.map(g => ({ id: g.id, name: g.name }))
  };
}

app.get('/api/org/tree', requireAuth('admin', 'operator'), (req, res) => {
  try {
    res.json(buildOrgTree());
  } catch (e) { sendServerError(res, e); }
});

// ─────────────────────────────────────────────
// ПОИСК ПО ОРГСТРУКТУРЕ (быстрый + с ИИ-подсказками)
// Всегда сначала делаем мгновенный поиск по всем уровням через LIKE.
// Если результатов мало (или запрос похож на "человеческий" вопрос),
// дополнительно просим Groq нормализовать/расширить запрос (опечатки,
// синонимы, извлечь номер курса и т.д.) и повторяем поиск уже с
// уточнёнными терминами, объединяя результаты.
// ─────────────────────────────────────────────
function orgFastSearch(q) {
  const like = `%${q}%`;
  const results = { faculties: [], departments: [], specialties: [], groups: [], students: [] };

  results.faculties = db.prepare(`SELECT id, name FROM faculties WHERE name LIKE ? LIMIT 10`).all(like);

  results.departments = db.prepare(`
    SELECT d.id, d.name, f.name as faculty_name, f.id as faculty_id
    FROM departments d JOIN faculties f ON f.id = d.faculty_id
    WHERE d.name LIKE ? LIMIT 10
  `).all(like);

  results.specialties = db.prepare(`
    SELECT s.id, s.name, d.name as department_name, f.name as faculty_name, f.id as faculty_id, d.id as department_id
    FROM specialties s
    JOIN departments d ON d.id = s.department_id
    JOIN faculties f ON f.id = d.faculty_id
    WHERE s.name LIKE ? LIMIT 10
  `).all(like);

  results.groups = db.prepare(`
    SELECT g.id, g.name, g.course, sp.name as specialty_name, dep.name as department_name, f.name as faculty_name
    FROM groups g
    LEFT JOIN specialties sp ON sp.id = g.specialty_id
    LEFT JOIN departments dep ON dep.id = g.department_id
    LEFT JOIN faculties f ON f.id = g.faculty_id
    WHERE g.name LIKE ? LIMIT 15
  `).all(like);

  results.students = db.prepare(`
    SELECT u.id, u.full_name, u.username, g.id as group_id, g.name as group_name
    FROM users u
    LEFT JOIN group_students gs ON gs.student_id = u.id
    LEFT JOIN groups g ON g.id = gs.group_id
    WHERE u.role = 'student' AND (u.full_name LIKE ? OR u.username LIKE ?)
    LIMIT 15
  `).all(like, like);

  return results;
}
function countResults(r) {
  return r.faculties.length + r.departments.length + r.specialties.length + r.groups.length + r.students.length;
}
function mergeResults(a, b) {
  const merged = {};
  ['faculties', 'departments', 'specialties', 'groups', 'students'].forEach(k => {
    const seen = new Set(a[k].map(x => x.id));
    merged[k] = [...a[k], ...b[k].filter(x => !seen.has(x.id))];
  });
  return merged;
}

app.get('/api/org/search', requireAuth('admin', 'operator', 'teacher'), async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    if (!q) return res.json({ faculties: [], departments: [], specialties: [], groups: [], students: [], ai_used: false });

    let results = orgFastSearch(q);
    let aiUsed = false;

    const looksNatural = q.split(/\s+/).length >= 3;
    if (GROQ_API_KEY && (countResults(results) < 2 || looksNatural)) {
      try {
        const aiResp = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${GROQ_API_KEY}` },
          body: JSON.stringify({
            model: 'openai/gpt-oss-120b',
            messages: [
              { role: 'system', content: 'Ты помогаешь исправлять опечатки и извлекать ключевые слова для поиска по учебной базе (факультеты, кафедры, специальности, группы, студенты). Отвечай СТРОГО в формате JSON без пояснений: {"keywords": ["слово1","слово2", ...]}. Верни 1-5 вероятных ключевых слов/фраз для полнотекстового поиска (LIKE), включая исправленные варианты написания и вероятное полное имя/название, если запрос — сокращение.' },
              { role: 'user', content: q }
            ],
            max_tokens: 200,
            temperature: 0.2
          })
        });
        const aiData = await aiResp.json();
        const raw = aiData?.choices?.[0]?.message?.content || '';
        const parsed = JSON.parse(raw.replace(/```json|```/g, '').trim());
        if (Array.isArray(parsed.keywords)) {
          aiUsed = true;
          for (const kw of parsed.keywords.slice(0, 5)) {
            if (kw && kw.trim() && kw.trim().toLowerCase() !== q.toLowerCase()) {
              results = mergeResults(results, orgFastSearch(kw.trim()));
            }
          }
        }
      } catch (e) {
        console.error('AI search enhancement failed (ignored, fast results still returned):', e.message);
      }
    }

    res.json({ ...results, ai_used: aiUsed });
  } catch (e) {
    sendServerError(res, e);
  }
});

// ─────────────────────────────────────────────
// ИИ-АНАЛИЗ ПРОБЛЕМНЫХ ЗОН ПО ВСЕЙ ОРГСТРУКТУРЕ
// Считает детерминированный рейтинг (по составному баллу = 0.6*балл + 0.4*
// посещаемость, взвешенно) для каждого уровня — лучший/худший факультет,
// кафедра, специальность, курс, группа — а затем просит ИИ дать связный
// анализ и рекомендации поверх этих реальных цифр.
// ─────────────────────────────────────────────
function compositeScore(node) {
  if (node.avg_grade_pct === null && node.avg_attendance_pct === null) return null;
  const g = node.avg_grade_pct ?? node.avg_attendance_pct;
  const a = node.avg_attendance_pct ?? node.avg_grade_pct;
  return Math.round(g * 0.6 + a * 0.4);
}
function rankNodes(nodes) {
  const withScore = nodes
    .map(n => ({ ...n, composite: compositeScore(n) }))
    .filter(n => n.composite !== null && n.students_count > 0);
  const sorted = [...withScore].sort((a, b) => b.composite - a.composite);
  return { sorted, best: sorted[0] || null, worst: sorted[sorted.length - 1] || null };
}

app.post('/api/ai-assistant/org-analysis', requireAuth('admin', 'operator'), async (req, res) => {
  try {
    const tree = buildOrgTree();

    const allDepartments = tree.faculties.flatMap(f => f.departments.map(d => ({ ...d, faculty_name: f.name })));
    const allSpecialties  = tree.faculties.flatMap(f => f.departments.flatMap(d => d.specialties.map(s => ({ ...s, department_name: d.name, faculty_name: f.name }))));
    const allGroups       = allSpecialties.flatMap(s => s.groups.map(g => ({ ...g, specialty_name: s.name, department_name: s.department_name, faculty_name: s.faculty_name })));

    const ranking = {
      faculties:   rankNodes(tree.faculties),
      departments: rankNodes(allDepartments),
      specialties: rankNodes(allSpecialties),
      groups:      rankNodes(allGroups),
      courses:     rankNodes(tree.course_breakdown.map(c => ({ ...c, name: `${c.course} курс` })))
    };

    let aiSummary = null;
    if (GROQ_API_KEY) {
      const fmt = (n) => n ? `${n.name} (балл ${n.avg_grade_pct ?? '—'}%, посещаемость ${n.avg_attendance_pct ?? '—'}%, студентов ${n.students_count})` : 'нет данных';
      const dataBlock = `
Итог по всей организации: средний балл ${tree.totals.avg_grade_pct ?? '—'}%, посещаемость ${tree.totals.avg_attendance_pct ?? '—'}%, всего студентов ${tree.totals.students_count}.

Факультеты — лучший: ${fmt(ranking.faculties.best)}; худший: ${fmt(ranking.faculties.worst)}.
Кафедры — лучшая: ${fmt(ranking.departments.best)}; худшая: ${fmt(ranking.departments.worst)}.
Специальности — лучшая: ${fmt(ranking.specialties.best)}; худшая: ${fmt(ranking.specialties.worst)}.
Курсы — лучший: ${fmt(ranking.courses.best)}; худший: ${fmt(ranking.courses.worst)}.
Группы — лучшая: ${fmt(ranking.groups.best)}; худшая: ${fmt(ranking.groups.worst)}.
`;
      try {
        const aiResp = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${GROQ_API_KEY}` },
          body: JSON.stringify({
            model: 'openai/gpt-oss-120b',
            messages: [
              { role: 'system', content: 'Ты аналитик образовательной организации. На основе реальных цифр по успеваемости объясни руководству, где основные проблемы, а где сильные стороны, и дай 3-5 конкретных приоритизированных рекомендаций. Пиши на русском, структурировано, без воды.' },
              { role: 'user', content: dataBlock }
            ],
            max_tokens: 900,
            temperature: 0.5
          })
        });
        const aiData = await aiResp.json();
        aiSummary = aiData?.choices?.[0]?.message?.content || null;
      } catch (e) {
        console.error('Org AI analysis failed (ignored, ranking still returned):', e.message);
      }
    }

    res.json({
      totals: tree.totals,
      ranking: {
        faculties:   { best: ranking.faculties.best,   worst: ranking.faculties.worst,   all: ranking.faculties.sorted },
        departments: { best: ranking.departments.best, worst: ranking.departments.worst, all: ranking.departments.sorted },
        specialties: { best: ranking.specialties.best, worst: ranking.specialties.worst, all: ranking.specialties.sorted },
        groups:      { best: ranking.groups.best,      worst: ranking.groups.worst,      all: ranking.groups.sorted },
        courses:     { best: ranking.courses.best,     worst: ranking.courses.worst,     all: ranking.courses.sorted }
      },
      ai_summary: aiSummary
    });
  } catch (e) {
    sendServerError(res, e);
  }
});

// Зачисление студентов в группу
app.post('/api/groups/:id/students', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const { student_id } = req.body;
    const student = db.prepare("SELECT id FROM users WHERE id = ? AND role = 'student'").get(student_id);
    if (!student) return res.status(404).json({ error: 'Студент не найден' });

    // Студент может состоять только в одной группе
    const already = db.prepare('SELECT group_id FROM group_students WHERE student_id = ?').get(student_id);
    if (already) return res.status(409).json({ error: 'Студент уже состоит в другой группе' });

    db.prepare('INSERT INTO group_students (group_id, student_id) VALUES (?, ?)').run(req.params.id, student_id);
    res.status(201).json({ success: true });
  } catch (e) { sendServerError(res, e); }
});

app.delete('/api/groups/:id/students/:student_id', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const link = db.prepare('SELECT 1 FROM group_students WHERE group_id = ? AND student_id = ?')
      .get(req.params.id, req.params.student_id);
    if (!link) return res.status(404).json({ error: 'Студент не состоит в этой группе' });

    db.prepare('DELETE FROM group_students WHERE group_id = ? AND student_id = ?')
      .run(req.params.id, req.params.student_id);
    logAudit(req.user, 'remove_student', 'group', parseInt(req.params.id), { student_id: parseInt(req.params.student_id) });
    res.json({ success: true });
  } catch (e) { sendServerError(res, e); }
});

// Назначение преподавателя (и его курса-плейлиста) на группу — даёт доступ к плейлисту студентам группы
app.post('/api/groups/:id/teachers', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const { teacher_id, playlist_id } = req.body;
    if (!teacher_id || !playlist_id) return res.status(400).json({ error: 'teacher_id и playlist_id обязательны' });

    const playlist = db.prepare('SELECT id FROM playlists WHERE id = ? AND teacher_id = ?').get(playlist_id, teacher_id);
    if (!playlist) return res.status(400).json({ error: 'Этот курс не принадлежит выбранному учителю' });

    const result = db.prepare('INSERT INTO group_teachers (group_id, teacher_id, playlist_id) VALUES (?, ?, ?)')
      .run(req.params.id, teacher_id, playlist_id);
    res.status(201).json({ id: result.lastInsertRowid });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'Уже назначено' });
    sendServerError(res, e);
  }
});

app.delete('/api/groups/:group_id/teachers/:assignment_id', requireAuth('admin', 'operator'), (req, res) => {
  try {
    db.prepare('DELETE FROM group_teachers WHERE id = ? AND group_id = ?')
      .run(req.params.assignment_id, req.params.group_id);
    res.json({ success: true });
  } catch (e) { sendServerError(res, e); }
});

// ─────────────────────────────────────────────
// ВИДЕОЗВОНКИ — состояние в памяти процесса
// ─────────────────────────────────────────────
// Архитектура: "звезда" вокруг учителя. Каждый студент держит одно
// RTCPeerConnection с учителем; учитель держит N соединений и является
// хабом/релеем для демонстрации экрана студента при scope='all'.
// Активные комнаты живут в памяти (быстрый realtime-доступ); в БД —
// только для истории. Рестарт сервера обрывает активные звонки — ожидаемо
// для WS-решения без внешнего брокера.
//
// videoRooms: Map<roomId, {
//   teacherId, title, groupIds:Set<number>,
//   participants: Map<userId, { ws, role, fullName, micEnabled, camEnabled,
//                                handRaised, screenSharing, screenScope }>
// }>
const videoRooms = new Map();

function studentInAnyGroup(studentId, groupIds) {
  if (!groupIds.length) return false;
  const placeholders = groupIds.map(() => '?').join(',');
  const row = db.prepare(
    `SELECT 1 FROM group_students WHERE student_id = ? AND group_id IN (${placeholders})`
  ).get(studentId, ...groupIds);
  return !!row;
}

// Активный звонок, актуальный для текущего пользователя (учитель — свой,
// студент — звонок в одной из его групп). Нужен для REST-поллинга, чтобы
// студент увидел уведомление о звонке даже не держа WS открытым заранее.
app.get('/api/video-rooms/active', requireAuth('teacher', 'student'), (req, res) => {
  try {
    let room = null;
    if (req.user.role === 'teacher') {
      room = db.prepare(`SELECT * FROM video_rooms WHERE teacher_id = ? AND status = 'active' ORDER BY id DESC LIMIT 1`)
        .get(req.user.id);
    } else {
      room = db.prepare(`
        SELECT vr.* FROM video_rooms vr
        JOIN video_room_groups vrg ON vrg.room_id = vr.id
        JOIN group_students gs ON gs.group_id = vrg.group_id
        WHERE vr.status = 'active' AND gs.student_id = ?
        ORDER BY vr.id DESC LIMIT 1
      `).get(req.user.id);
    }
    if (!room) return res.json({ room: null });

    const teacher = db.prepare('SELECT full_name FROM users WHERE id = ?').get(room.teacher_id);
    const groupIds = db.prepare('SELECT group_id FROM video_room_groups WHERE room_id = ?')
      .all(room.id).map(r => r.group_id);
    res.json({
      room: {
        id: room.id, title: room.title, teacher_id: room.teacher_id,
        teacher_name: teacher ? teacher.full_name : null, group_ids: groupIds
      }
    });
  } catch (e) { sendServerError(res, e); }
});

// История участников звонка (для журнала посещаемости) — не блокер первой
// итерации, но данные уже пишутся в video_room_participants.
app.get('/api/video-rooms/:id/participants', requireAuth('teacher', 'admin', 'operator'), (req, res) => {
  try {
    const room = db.prepare('SELECT * FROM video_rooms WHERE id = ?').get(req.params.id);
    if (!room) return res.status(404).json({ error: 'Звонок не найден' });
    if (req.user.role === 'teacher' && room.teacher_id !== req.user.id) {
      return res.status(403).json({ error: 'Нет доступа' });
    }
    const rows = db.prepare(`
      SELECT vrp.*, u.full_name, u.username, u.role
      FROM video_room_participants vrp
      JOIN users u ON u.id = vrp.user_id
      WHERE vrp.room_id = ?
      ORDER BY vrp.joined_at ASC
    `).all(req.params.id);
    res.json({ room, participants: rows });
  } catch (e) { sendServerError(res, e); }
});

// ─────────────────────────────────────────────
// API: РАСПИСАНИЕ
// ─────────────────────────────────────────────
app.get('/api/schedule', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    let query = `
      SELECT s.*, g.name as group_name, p.title as playlist_title, u.full_name as teacher_name
      FROM schedule s
      JOIN groups g ON g.id = s.group_id
      LEFT JOIN playlists p ON p.id = s.playlist_id
      LEFT JOIN users u ON u.id = s.teacher_id
      WHERE 1=1
    `;
    const params = [];

    if (req.user.role === 'student') {
      const group = getStudentGroup(req.user.id);
      if (!group) return res.json([]);
      query += ' AND s.group_id = ?';
      params.push(group.id);
    } else if (req.user.role === 'teacher') {
      query += ' AND s.teacher_id = ?';
      params.push(req.user.id);
    } else if (req.query.group_id) {
      query += ' AND s.group_id = ?';
      params.push(req.query.group_id);
    }

    query += ' ORDER BY s.day_of_week ASC, s.start_time ASC';
    res.json(db.prepare(query).all(...params));
  } catch (e) { sendServerError(res, e); }
});

app.post('/api/schedule', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const { group_id, playlist_id, teacher_id, day_of_week, lesson_date, start_time, end_time, room, subject_title } = req.body;
    if (!group_id || !start_time || !end_time)
      return res.status(400).json({ error: 'group_id, start_time, end_time обязательны' });

    const result = db.prepare(`
      INSERT INTO schedule (group_id, playlist_id, teacher_id, day_of_week, lesson_date, start_time, end_time, room, subject_title)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(group_id, playlist_id || null, teacher_id || null, day_of_week || null, lesson_date || null,
           start_time, end_time, room || '', subject_title || '');

    res.status(201).json(db.prepare('SELECT * FROM schedule WHERE id = ?').get(result.lastInsertRowid));
  } catch (e) { sendServerError(res, e); }
});

app.put('/api/schedule/:id', requireAuth('admin', 'operator'), (req, res) => {
  try {
    const { group_id, playlist_id, teacher_id, day_of_week, lesson_date, start_time, end_time, room, subject_title } = req.body;
    const existing = db.prepare('SELECT * FROM schedule WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Запись не найдена' });

    db.prepare(`
      UPDATE schedule SET group_id=?, playlist_id=?, teacher_id=?, day_of_week=?, lesson_date=?,
        start_time=?, end_time=?, room=?, subject_title=? WHERE id=?
    `).run(
      group_id ?? existing.group_id, playlist_id ?? existing.playlist_id, teacher_id ?? existing.teacher_id,
      day_of_week ?? existing.day_of_week, lesson_date ?? existing.lesson_date,
      start_time ?? existing.start_time, end_time ?? existing.end_time,
      room ?? existing.room, subject_title ?? existing.subject_title, req.params.id
    );
    res.json(db.prepare('SELECT * FROM schedule WHERE id = ?').get(req.params.id));
  } catch (e) { sendServerError(res, e); }
});

app.delete('/api/schedule/:id', requireAuth('admin', 'operator'), (req, res) => {
  try {
    db.prepare('DELETE FROM schedule WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  } catch (e) { sendServerError(res, e); }
});

// ─────────────────────────────────────────────
// API: ТЕСТЫ
// ─────────────────────────────────────────────

// GET /api/quizzes — список тестов
app.get('/api/quizzes', requireAuth('admin', 'teacher', 'student'), (req, res) => {
  try {
    const lessonId = req.query.lesson_id ? parseInt(req.query.lesson_id) : null;
    let quizzes;
    if (req.user.role === 'teacher') {
      quizzes = db.prepare(`
        SELECT q.*, u.full_name as teacher_name,
               COUNT(qq.id) as question_count
        FROM quizzes q
        JOIN users u ON u.id = q.teacher_id
        LEFT JOIN quiz_questions qq ON qq.quiz_id = q.id
        WHERE q.teacher_id = ? ${lessonId ? 'AND q.lesson_id = ?' : ''}
        GROUP BY q.id
        ORDER BY q.created_at DESC
      `).all(...(lessonId ? [req.user.id, lessonId] : [req.user.id]));
    } else if (req.user.role === 'student') {
      quizzes = db.prepare(`
        SELECT q.*, u.full_name as teacher_name,
               COUNT(qq.id) as question_count
        FROM quizzes q
        JOIN users u ON u.id = q.teacher_id
        LEFT JOIN quiz_questions qq ON qq.quiz_id = q.id
        WHERE (q.playlist_id IS NULL
           OR q.playlist_id IN (
             SELECT gt.playlist_id FROM group_teachers gt
             JOIN group_students gs ON gs.group_id = gt.group_id
             WHERE gs.student_id = ?
           )) ${lessonId ? 'AND q.lesson_id = ?' : ''}
        GROUP BY q.id
        ORDER BY q.created_at DESC
      `).all(...(lessonId ? [req.user.id, lessonId] : [req.user.id]));
    } else {
      quizzes = db.prepare(`
        SELECT q.*, u.full_name as teacher_name,
               COUNT(qq.id) as question_count
        FROM quizzes q
        JOIN users u ON u.id = q.teacher_id
        LEFT JOIN quiz_questions qq ON qq.quiz_id = q.id
        ${lessonId ? 'WHERE q.lesson_id = ?' : ''}
        GROUP BY q.id
        ORDER BY q.created_at DESC
      `).all(...(lessonId ? [lessonId] : []));
    }
    res.json(quizzes);
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/quizzes — создать тест (только учитель)
app.post('/api/quizzes', requireAuth('teacher'), (req, res) => {
  uploadQuiz(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    const sigErr = validateUploadSignatures(req.files || []);
    if (sigErr) return res.status(400).json({ error: sigErr });

    try {
      const { title, questions: questionsRaw, control_type, playlist_id, lesson_id, max_attempts } = req.body;
      if (!title) return res.status(400).json({ error: 'Название теста обязательно' });

      let maxAttempts = null;
      if (max_attempts !== undefined && max_attempts !== null && max_attempts !== '') {
        const n = parseInt(max_attempts);
        if (!Number.isInteger(n) || n < 1) return res.status(400).json({ error: 'Лимит попыток должен быть целым числом не меньше 1' });
        maxAttempts = n;
      }

      let ctype = ['lesson', 'checkpoint1', 'checkpoint2', 'session'].includes(control_type) ? control_type : 'lesson';
      let finalPlaylistId = playlist_id || null;

      if (lesson_id) {
        // Тест привязан к конкретному уроку — курс и роль владельца определяем по уроку
        const lesson = db.prepare(`
          SELECT l.*, p.teacher_id, p.id as playlist_id
          FROM lessons l JOIN playlists p ON p.id = l.playlist_id
          WHERE l.id = ?
        `).get(lesson_id);
        if (!lesson) return res.status(404).json({ error: 'Урок не найден' });
        if (lesson.teacher_id !== req.user.id) return res.status(403).json({ error: 'Нет доступа к этому уроку' });
        const existingQuiz = db.prepare('SELECT id FROM quizzes WHERE lesson_id = ?').get(lesson_id);
        if (existingQuiz) return res.status(409).json({ error: 'К этому уроку уже привязан тест — сначала удалите его' });
        ctype = 'lesson';
        finalPlaylistId = lesson.playlist_id;
      } else {
        if (ctype !== 'lesson' && !finalPlaylistId)
          return res.status(400).json({ error: 'Для экзамена рубежки/сессии нужно указать курс (playlist_id)' });
        if (finalPlaylistId) {
          const pl = db.prepare('SELECT id FROM playlists WHERE id = ? AND teacher_id = ?').get(finalPlaylistId, req.user.id);
          if (!pl) return res.status(403).json({ error: 'Нет доступа к этому курсу' });
          if (ctype !== 'lesson') {
            const dup = db.prepare('SELECT id FROM quizzes WHERE playlist_id = ? AND control_type = ?').get(finalPlaylistId, ctype);
            if (dup) return res.status(409).json({ error: 'Для этого этапа уже настроен экзамен' });
          }
        }
      }

      let questions = [];
      if (questionsRaw) {
        try { questions = JSON.parse(questionsRaw); }
        catch { return res.status(400).json({ error: 'Неверный формат вопросов (JSON)' }); }
      }

      // Строим карту загруженных файлов изображений
      const files = {};
      for (const f of (req.files || [])) {
        files[f.fieldname] = fileUrl(f.filename);
      }

      // Создаём тест
      const quizResult = db.prepare(`
        INSERT INTO quizzes (title, teacher_id, playlist_id, control_type, lesson_id, max_attempts) VALUES (?, ?, ?, ?, ?, ?)
      `).run(title, req.user.id, finalPlaylistId, ctype, lesson_id || null, maxAttempts);
      const quizId = quizResult.lastInsertRowid;

      // Создаём вопросы и варианты ответов
      const insertQuestion = db.prepare(`
        INSERT INTO quiz_questions
          (quiz_id, question_text, question_image_path, multiple_correct, order_index)
        VALUES (?, ?, ?, ?, ?)
      `);
      const insertOption = db.prepare(`
        INSERT INTO quiz_options
          (question_id, option_text, option_image_path, is_correct)
        VALUES (?, ?, ?, ?)
      `);

      questions.forEach((q, qi) => {
        const qImgKey  = `question_image_${qi}`;
        const qImgPath = files[qImgKey] || null;

        const qResult = insertQuestion.run(
          quizId,
          q.question_text  || null,
          qImgPath,
          q.multiple_correct ? 1 : 0,
          qi
        );
        const questionId = qResult.lastInsertRowid;

        (q.options || []).forEach((opt, oi) => {
          const oImgKey  = `option_image_${qi}_${oi}`;
          const oImgPath = files[oImgKey] || null;
          insertOption.run(
            questionId,
            opt.option_text || null,
            oImgPath,
            opt.is_correct  ? 1 : 0
          );
        });
      });

      res.status(201).json({ id: quizId, title, teacher_id: req.user.id });
    } catch (e) {
      sendServerError(res, e);
    }
  });
});
// GET /api/quizzes/import-template — шаблон Excel для автоматического создания теста
// ВАЖНО: должен идти ДО '/api/quizzes/:id', иначе Express перехватит "import-template" как :id
app.get('/api/quizzes/import-template', requireAuth('teacher'), (req, res) => {
  const rows = [
    ['Вопрос', 'Вариант A', 'Вариант B', 'Вариант C', 'Вариант D', 'Правильный ответ (например A или A,C)'],
    ['Сколько будет 2+2?', '3', '4', '5', '22', 'B'],
    ['Какие из чисел чётные?', '2', '3', '4', '7', 'A,C']
  ];
  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet(rows);
  ws['!cols'] = [{ wch: 40 }, { wch: 20 }, { wch: 20 }, { wch: 20 }, { wch: 20 }, { wch: 30 }];
  XLSX.utils.book_append_sheet(wb, ws, 'Тест');
  const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename="shablon_importa_testa.xlsx"');
  res.send(buf);
});

// POST /api/quizzes/import — автоматически создать тест из Excel/CSV файла (для конкретного урока)
app.post('/api/quizzes/import', requireAuth('teacher'), (req, res) => {
  uploadImport(req, res, (err) => {
    if (err) return res.status(400).json({ error: 'Ошибка загрузки файла: ' + err.message });
    if (!req.file) return res.status(400).json({ error: 'Файл не прикреплён' });

    try {
      const { title, lesson_id } = req.body;
      if (!title || !title.trim()) return res.status(400).json({ error: 'Укажите название теста' });
      if (!lesson_id) return res.status(400).json({ error: 'Не указан урок' });

      const lesson = db.prepare(`
        SELECT l.*, p.teacher_id, p.id as playlist_id
        FROM lessons l JOIN playlists p ON p.id = l.playlist_id
        WHERE l.id = ?
      `).get(lesson_id);
      if (!lesson) return res.status(404).json({ error: 'Урок не найден' });
      if (lesson.teacher_id !== req.user.id) return res.status(403).json({ error: 'Нет доступа к этому уроку' });
      const existingQuiz = db.prepare('SELECT id FROM quizzes WHERE lesson_id = ?').get(lesson_id);
      if (existingQuiz) return res.status(409).json({ error: 'К этому уроку уже привязан тест — сначала удалите его' });

      // Та же проблема с кодировкой CSV, что и в /api/users/import — см. комментарий там.
      const isCsvQuiz = /\.csv$/i.test(req.file.originalname || '');
      const wb = isCsvQuiz
        ? XLSX.read(req.file.buffer.toString('utf8'), { type: 'string' })
        : XLSX.read(req.file.buffer, { type: 'buffer' });
      const sheet = wb.Sheets[wb.SheetNames[0]];
      const rawRows = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '' });
      const dataRows = rawRows.slice(1).filter(r => String(r[0] || '').trim()); // пропускаем заголовок и пустые строки
      if (!dataRows.length) return res.status(400).json({ error: 'В файле нет строк с вопросами. Скачайте шаблон и заполните по образцу.' });

      const parsedQuestions = [];
      const errors = [];
      dataRows.forEach((row, idx) => {
        const rowNum = idx + 2;
        const questionText = String(row[0] || '').trim();
        const optionTexts = [1, 2, 3, 4].map(i => String(row[i] || '').trim()).filter(Boolean);
        const correctRaw = String(row[5] || '').trim().toUpperCase();
        if (!questionText) { errors.push({ row: rowNum, error: 'Пустой вопрос' }); return; }
        if (optionTexts.length < 2) { errors.push({ row: rowNum, error: 'Нужно минимум 2 варианта ответа' }); return; }
        if (!correctRaw) { errors.push({ row: rowNum, error: 'Не указан правильный ответ' }); return; }

        const letterToIndex = { A: 0, B: 1, C: 2, D: 3 };
        const correctLetters = correctRaw.split(/[,\s]+/).filter(Boolean);
        const correctIndexes = correctLetters.map(l => letterToIndex[l]).filter(i => i !== undefined && i < optionTexts.length);
        if (!correctIndexes.length) { errors.push({ row: rowNum, error: 'Некорректный правильный ответ (используйте A, B, C, D)' }); return; }

        parsedQuestions.push({
          question_text: questionText,
          multiple_correct: correctIndexes.length > 1,
          options: optionTexts.map((text, i) => ({ option_text: text, is_correct: correctIndexes.includes(i) }))
        });
      });

      if (!parsedQuestions.length)
        return res.status(400).json({ error: 'Не удалось распознать ни одного вопроса', details: errors });

      const quizResult = db.prepare(`
        INSERT INTO quizzes (title, teacher_id, playlist_id, control_type, lesson_id) VALUES (?, ?, ?, 'lesson', ?)
      `).run(title.trim(), req.user.id, lesson.playlist_id, lesson_id);
      const quizId = quizResult.lastInsertRowid;

      const insertQuestion = db.prepare(`
        INSERT INTO quiz_questions (quiz_id, question_text, multiple_correct, order_index) VALUES (?, ?, ?, ?)
      `);
      const insertOption = db.prepare(`
        INSERT INTO quiz_options (question_id, option_text, is_correct) VALUES (?, ?, ?)
      `);
      parsedQuestions.forEach((q, qi) => {
        const qResult = insertQuestion.run(quizId, q.question_text, q.multiple_correct ? 1 : 0, qi);
        q.options.forEach(opt => insertOption.run(qResult.lastInsertRowid, opt.option_text, opt.is_correct ? 1 : 0));
      });

      res.status(201).json({
        id: quizId, title: title.trim(), question_count: parsedQuestions.length,
        skipped: errors.length, errors
      });
    } catch (e) {
      sendServerError(res, e);
    }
  });
});

// GET /api/quizzes/:id — получить тест с вопросами и вариантами
app.get('/api/quizzes/:id', requireAuth('admin', 'teacher', 'student'), (req, res) => {
  try {
    const quiz = db.prepare(`
      SELECT q.*, u.full_name as teacher_name
      FROM quizzes q
      JOIN users u ON u.id = q.teacher_id
      WHERE q.id = ?
    `).get(req.params.id);
    if (!quiz) return res.status(404).json({ error: 'Тест не найден' });

    // Студент может открыть только тест из плейлиста, назначенного его группе
    if (req.user.role === 'student' && !studentHasPlaylistAccess(req.user.id, quiz.playlist_id))
      return res.status(403).json({ error: 'Нет доступа к этому тесту' });

    // Гейт: студент не может открыть вопросы теста, пока не досмотрел видео урока
    if (req.user.role === 'student' && quiz.lesson_id) {
      const quizLesson = db.prepare('SELECT video_2d_path FROM lessons WHERE id = ?').get(quiz.lesson_id);
      if (quizLesson && quizLesson.video_2d_path) {
        const progress = db.prepare(`
          SELECT is_completed FROM lesson_progress WHERE student_id = ? AND lesson_id = ?
        `).get(req.user.id, quiz.lesson_id);
        if (!progress || !progress.is_completed) {
          return res.status(403).json({ error: 'Досмотрите видео урока до конца, чтобы открыть тест' });
        }
      }
    }

    const questions = db.prepare(`
      SELECT * FROM quiz_questions
      WHERE quiz_id = ?
      ORDER BY order_index ASC
    `).all(quiz.id);

    for (const q of questions) {
      let options = db.prepare(`
        SELECT * FROM quiz_options WHERE question_id = ?
      `).all(q.id);

      // Студент не видит правильные ответы
      if (req.user.role === 'student') {
        options = options.map(o => ({
          id:               o.id,
          question_id:      o.question_id,
          option_text:      o.option_text,
          option_image_path: o.option_image_path
        }));
      }
      q.options = options;
    }

    quiz.questions = questions;
    res.json(quiz);
  } catch (e) {
    sendServerError(res, e);
  }
});

// PUT /api/quizzes/:id — редактировать тест (название, лимит попыток по решению преподавателя)
app.put('/api/quizzes/:id', requireAuth('teacher', 'admin'), (req, res) => {
  try {
    const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ?').get(req.params.id);
    if (!quiz) return res.status(404).json({ error: 'Тест не найден' });
    if (req.user.role === 'teacher' && quiz.teacher_id !== req.user.id)
      return res.status(403).json({ error: 'Нет доступа' });

    const { title, max_attempts } = req.body;

    let maxAttempts = quiz.max_attempts;
    if (max_attempts !== undefined) {
      if (max_attempts === null || max_attempts === '') {
        maxAttempts = null; // без ограничений
      } else {
        const n = parseInt(max_attempts);
        if (!Number.isInteger(n) || n < 1) return res.status(400).json({ error: 'Лимит попыток должен быть целым числом не меньше 1' });
        maxAttempts = n;
      }
    }

    db.prepare('UPDATE quizzes SET title = ?, max_attempts = ? WHERE id = ?')
      .run((title || quiz.title || '').trim() || quiz.title, maxAttempts, quiz.id);

    res.json(db.prepare('SELECT * FROM quizzes WHERE id = ?').get(quiz.id));
  } catch (e) {
    sendServerError(res, e);
  }
});

// DELETE /api/quizzes/:id — удалить тест (только учитель/админ)
app.delete('/api/quizzes/:id', requireAuth('teacher', 'admin'), (req, res) => {
  try {
    const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ?').get(req.params.id);
    if (!quiz) return res.status(404).json({ error: 'Тест не найден' });

    if (req.user.role === 'teacher' && quiz.teacher_id !== req.user.id)
      return res.status(403).json({ error: 'Нет доступа' });

    // Удаляем изображения вопросов и вариантов
    const questions = db.prepare(
      'SELECT * FROM quiz_questions WHERE quiz_id = ?'
    ).all(quiz.id);

    for (const q of questions) {
      if (q.question_image_path) deleteFile(q.question_image_path);
      const options = db.prepare(
        'SELECT * FROM quiz_options WHERE question_id = ?'
      ).all(q.id);
      for (const o of options) {
        if (o.option_image_path) deleteFile(o.option_image_path);
      }
    }

    db.prepare('DELETE FROM quizzes WHERE id = ?').run(quiz.id);
    res.json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/quizzes/:id/submit — сдать тест (только студент)
app.post('/api/quizzes/:id/submit', requireAuth('student'), (req, res) => {
  try {
    const { id }      = req.params;
    const { answers } = req.body; // [{question_id, selected_option_ids: [int,...]}]

    if (!answers || !Array.isArray(answers))
      return res.status(400).json({ error: 'answers обязателен (массив)' });

    const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ?').get(id);
    if (!quiz) return res.status(404).json({ error: 'Тест не найден' });

    if (!studentHasPlaylistAccess(req.user.id, quiz.playlist_id))
      return res.status(403).json({ error: 'Нет доступа к этому тесту' });

    // Гейт: если тест привязан к уроку с видео — нельзя сдать тест,
    // пока видео урока не досмотрено до конца (аналогично гейту для ДЗ)
    if (quiz.lesson_id) {
      const quizLesson = db.prepare('SELECT video_2d_path FROM lessons WHERE id = ?').get(quiz.lesson_id);
      if (quizLesson && quizLesson.video_2d_path) {
        const progress = db.prepare(`
          SELECT is_completed FROM lesson_progress WHERE student_id = ? AND lesson_id = ?
        `).get(req.user.id, quiz.lesson_id);
        if (!progress || !progress.is_completed) {
          return res.status(403).json({ error: 'Досмотрите видео урока до конца, чтобы открыть отправку теста' });
        }
      }
    }

    // Ограничение попыток сдачи — по решению преподавателя (quiz.max_attempts)
    if (quiz.max_attempts) {
      const attemptsUsed = db.prepare(
        'SELECT COUNT(*) as c FROM quiz_results WHERE quiz_id = ? AND student_id = ?'
      ).get(id, req.user.id).c;
      if (attemptsUsed >= quiz.max_attempts) {
        return res.status(403).json({
          error: `Лимит попыток исчерпан (${attemptsUsed}/${quiz.max_attempts}). Преподаватель установил ограничение на количество попыток сдачи этого теста.`,
          attempts_used: attemptsUsed,
          max_attempts: quiz.max_attempts
        });
      }
    }

    // Проверка последовательности допуска к экзаменам рубежки/сессии
    if (quiz.control_type === 'checkpoint1' && !weeklyComplete(req.user.id, quiz.playlist_id))
      return res.status(403).json({ error: 'Сначала должны быть выставлены все недельные оценки по курсу' });
    if (quiz.control_type === 'checkpoint2' && !getControlGrade(req.user.id, quiz.playlist_id, 'checkpoint1'))
      return res.status(403).json({ error: 'Сначала должен быть выставлен рубежный контроль 1' });
    if (quiz.control_type === 'session' && (!getControlGrade(req.user.id, quiz.playlist_id, 'checkpoint1') || !getControlGrade(req.user.id, quiz.playlist_id, 'checkpoint2')))
      return res.status(403).json({ error: 'Сначала должны быть выставлены оба рубежных контроля' });

    const questions = db.prepare(`
      SELECT * FROM quiz_questions WHERE quiz_id = ? ORDER BY order_index ASC
    `).all(id);

    let score   = 0;
    const total = questions.length;
    const details = [];

    for (const question of questions) {
      const allOptions = db.prepare(
        'SELECT * FROM quiz_options WHERE question_id = ?'
      ).all(question.id);

      const correctIds = allOptions
        .filter(o => o.is_correct === 1)
        .map(o => o.id);

      const answer = answers.find(a => a.question_id === question.id);
      const selectedIds = answer ? (answer.selected_option_ids || []) : [];

      let isCorrect = false;

      if (question.multiple_correct === 0) {
        // Один правильный ответ: выбран ровно один и он правильный
        isCorrect = selectedIds.length === 1 && correctIds.includes(selectedIds[0]);
      } else {
        // Несколько правильных: все правильные выбраны и ничего лишнего
        const selectedSet = new Set(selectedIds);
        const correctSet  = new Set(correctIds);
        isCorrect =
          selectedSet.size === correctSet.size &&
          [...correctSet].every(cid => selectedSet.has(cid));
      }

      if (isCorrect) score++;
      details.push({ question_id: question.id, correct: isCorrect });
    }

    // Сохраняем результат
    const result = db.prepare(`
      INSERT INTO quiz_results (quiz_id, student_id, score, total)
      VALUES (?, ?, ?, ?)
    `).run(id, req.user.id, score, total);

    // Если это экзамен сессии — пробуем автоматически выставить итоговую оценку
    if (quiz.control_type === 'session' && quiz.playlist_id) {
      maybeCreateSessionGrade(req.user.id, quiz.playlist_id);
    }

    // Если тест привязан к конкретному уроку — автоматически выставляем оценку в журнал за урок
    const percent = total > 0 ? Math.round((score / total) * 100) : 0;
    if (quiz.lesson_id) {
      upsertWeeklyGradeFromHomework(
        req.user.id, quiz.lesson_id, quiz.playlist_id, quiz.teacher_id,
        percent, `Автоматически по результатам теста: ${score}/${total}`, 'auto'
      );
    }

    const attemptsUsedNow = db.prepare(
      'SELECT COUNT(*) as c FROM quiz_results WHERE quiz_id = ? AND student_id = ?'
    ).get(id, req.user.id).c;

    res.json({
      id:           result.lastInsertRowid,
      quiz_id:      parseInt(id),
      score,
      total,
      percent,
      details,
      completed_at: new Date().toISOString(),
      attempts_used: attemptsUsedNow,
      max_attempts:  quiz.max_attempts || null
    });
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/quizzes/:id/results — результаты теста (учитель/админ)
app.get('/api/quizzes/:id/results', requireAuth('teacher', 'admin'), (req, res) => {
  try {
    const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ?').get(req.params.id);
    if (!quiz) return res.status(404).json({ error: 'Тест не найден' });

    if (req.user.role === 'teacher' && quiz.teacher_id !== req.user.id)
      return res.status(403).json({ error: 'Нет доступа' });

    const results = db.prepare(`
      SELECT qr.*,
             u.full_name  as student_name,
             u.username   as student_username,
             ROUND(CAST(qr.score AS FLOAT) / qr.total * 100) as percent
      FROM quiz_results qr
      JOIN users u ON u.id = qr.student_id
      WHERE qr.quiz_id = ?
      ORDER BY qr.id DESC
    `).all(req.params.id);

    res.json(results);
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/quizzes/:id/my-result — мой последний результат (студент)
app.get('/api/quizzes/:id/my-result', requireAuth('student'), (req, res) => {
  try {
    const quiz = db.prepare('SELECT max_attempts FROM quizzes WHERE id = ?').get(req.params.id);
    // БАГ (найден и исправлен): сортировка по completed_at (текстовая
    // секундная точность) не гарантирует последнюю попытку при повторной
    // сдаче в пределах одной секунды — сортируем по id, он растёт монотонно.
    const result = db.prepare(`
      SELECT * FROM quiz_results
      WHERE quiz_id = ? AND student_id = ?
      ORDER BY id DESC
      LIMIT 1
    `).get(req.params.id, req.user.id);
    const attemptsUsed = db.prepare(
      'SELECT COUNT(*) as c FROM quiz_results WHERE quiz_id = ? AND student_id = ?'
    ).get(req.params.id, req.user.id).c;

    res.json({
      ...(result || null),
      has_result:    !!result,
      attempts_used: attemptsUsed,
      max_attempts:  quiz ? (quiz.max_attempts || null) : null,
      attempts_left: quiz && quiz.max_attempts ? Math.max(0, quiz.max_attempts - attemptsUsed) : null
    });
  } catch (e) {
    sendServerError(res, e);
  }
});

// ─────────────────────────────────────────────
// API: УВЕДОМЛЕНИЯ
// ─────────────────────────────────────────────

// GET /api/notifications — мои уведомления (последние 50) + счётчик непрочитанных
app.get('/api/notifications', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    const notifications = db.prepare(`
      SELECT * FROM notifications
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 50
    `).all(req.user.id);

    const unread = db.prepare(`
      SELECT COUNT(*) as c FROM notifications WHERE user_id = ? AND is_read = 0
    `).get(req.user.id).c;

    res.json({ notifications, unread });
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/notifications/:id/read — отметить одно уведомление прочитанным
app.post('/api/notifications/:id/read', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    const notif = db.prepare('SELECT * FROM notifications WHERE id = ?').get(req.params.id);
    if (!notif) return res.status(404).json({ error: 'Уведомление не найдено' });
    if (notif.user_id !== req.user.id) return res.status(403).json({ error: 'Нет доступа' });

    db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/notifications/read-all — отметить все прочитанными
app.post('/api/notifications/read-all', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0').run(req.user.id);
    res.json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// ─────────────────────────────────────────────
// API: РЕЗЕРВНЫЕ КОПИИ БД (только admin)
// ─────────────────────────────────────────────
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

// GET /api/admin/backups — список существующих бэкапов
app.get('/api/admin/backups', requireAuth('admin'), (req, res) => {
  try {
    const files = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith('database-') && f.endsWith('.db'))
      .map(f => {
        const stat = fs.statSync(path.join(BACKUP_DIR, f));
        return { name: f, size_bytes: stat.size, created_at: stat.mtime.toISOString() };
      })
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.json(files);
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/admin/backups — создать бэкап прямо сейчас
app.post('/api/admin/backups', requireAuth('admin'), async (req, res) => {
  try {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = path.join(BACKUP_DIR, `database-${stamp}.db`);
    await db.backup(backupPath);
    logAudit(req.user, 'create_backup', 'database', null, { file: `database-${stamp}.db` });
    res.status(201).json({ success: true, file: `database-${stamp}.db` });
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/admin/backups/:name/download — скачать конкретный файл бэкапа
app.get('/api/admin/backups/:name/download', requireAuth('admin'), (req, res) => {
  const name = req.params.name;
  if (!/^database-[\w.-]+\.db$/.test(name))
    return res.status(400).json({ error: 'Некорректное имя файла' });
  const filePath = path.join(BACKUP_DIR, name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Файл не найден' });
  res.download(filePath, name);
});

// ─────────────────────────────────────────────
// API: АУДИТ-ЛОГ (только admin)
// ─────────────────────────────────────────────
// GET /api/admin/audit-log?page=1&limit=50&entity=user&action=create
app.get('/api/admin/audit-log', requireAuth('admin'), (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit) || 50));
    const offset = (page - 1) * limit;

    const where = [];
    const params = [];
    if (req.query.entity) { where.push('entity = ?'); params.push(req.query.entity); }
    if (req.query.action) { where.push('action = ?'); params.push(req.query.action); }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const total = db.prepare(`SELECT COUNT(*) as c FROM audit_log ${whereSql}`).get(...params).c;
    const logs = db.prepare(`
      SELECT * FROM audit_log ${whereSql}
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    res.json({ logs, total, page, limit, pages: Math.max(1, Math.ceil(total / limit)) });
  } catch (e) {
    sendServerError(res, e);
  }
});

// ─────────────────────────────────────────────
// API: СТАТИСТИКА (только admin)
// ─────────────────────────────────────────────
app.get('/api/stats', requireAuth('admin'), (req, res) => {
  try {
    const totalUsers    = db.prepare("SELECT COUNT(*) as c FROM users").get().c;
    const totalStudents = db.prepare("SELECT COUNT(*) as c FROM users WHERE role='student'").get().c;
    const totalTeachers = db.prepare("SELECT COUNT(*) as c FROM users WHERE role='teacher'").get().c;
    const totalLessons  = db.prepare("SELECT COUNT(*) as c FROM lessons").get().c;
    const totalQuizzes  = db.prepare("SELECT COUNT(*) as c FROM quizzes").get().c;
    const totalHW       = db.prepare("SELECT COUNT(*) as c FROM homework_submissions").get().c;
    const pendingHW     = db.prepare(
      "SELECT COUNT(*) as c FROM homework_submissions WHERE grade IS NULL"
    ).get().c;

    const recentUsers = db.prepare(`
      SELECT id, username, full_name, role, created_at
      FROM users ORDER BY created_at DESC LIMIT 5
    `).all();

    res.json({
      totalUsers, totalStudents, totalTeachers,
      totalLessons, totalQuizzes,
      totalHW, pendingHW,
      recentUsers
    });
  } catch (e) {
    sendServerError(res, e);
  }
});

// ════════════════════════════════════════════
// API: AR ПОМОЩНИЦА — GROQ AI (не путать с xAI/Grok!)
// ════════════════════════════════════════════
// GROQ_API_KEY теперь приходит из ./config (см. импорт в начале файла).

app.post('/api/ai-assistant', requireAuth('student','teacher'), async (req, res) => {
  try {
    if (!GROQ_API_KEY) {
      return res.status(503).json({ error: 'AI-помощница временно недоступна: не настроен GROQ_API_KEY на сервере' });
    }

    const { question, lesson_title, lesson_description } = req.body;
    if (!question) return res.status(400).json({ error: 'Вопрос обязателен' });

    // Формируем контекст урока для Groq
    const systemPrompt = `Ты — AI помощница по имени Айгуль на образовательной платформе ЕдуПортал. 
Ты помогаешь студентам понять материал урока.
Текущий урок: "${lesson_title || 'Неизвестный урок'}".
Описание урока: "${lesson_description || 'Описание отсутствует'}".
Отвечай чётко, понятно, дружелюбно. Если вопрос не по теме урока — мягко направь студента к теме.
Отвечай на том же языке на котором задан вопрос (русский или казахский).`;

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${GROQ_API_KEY}`
      },
      body: JSON.stringify({
        model:       'openai/gpt-oss-120b',
        messages: [
          { role: 'system',  content: systemPrompt },
          { role: 'user',    content: question }
        ],
        max_tokens:  500,
        temperature: 0.7
      })
    });

    const data = await response.json();
    if (data.error) {
      console.error('Groq API error:', data.error);
      return res.status(500).json({ error: data.error.message });
    }
    if (!response.ok || !data.choices || !data.choices[0]) {
      console.error('Groq API bad response:', response.status, JSON.stringify(data));
      return res.status(500).json({ error: 'Groq вернул некорректный ответ' });
    }

    const answer = data.choices[0].message.content;
    res.json({ answer });

  } catch(e) {
    console.error('AI assistant error:', e);
    res.status(500).json({ error: 'Ошибка AI: ' + e.message });
  }
});

// ════════════════════════════════════════════
// API: AI-АССИСТЕНТ ДЛЯ УЧИТЕЛЯ — планы уроков, отчёты, сводки по группе
// ════════════════════════════════════════════
// action:
//   'lesson_plan' — план урока по теме/классу/длительности
//   'report'      — текстовый отчёт по успеваемости группы (использует /api/groups/:id/performance)
//   'summary'     — краткая аналитика + рекомендации по группе
//   'custom'      — свободный вопрос ассистенту (рутинные задачи: письмо родителям, объявление и т.д.)
app.post('/api/ai-assistant/teacher', requireAuth('teacher'), async (req, res) => {
  try {
    if (!GROQ_API_KEY) {
      return res.status(503).json({ error: 'AI-помощница временно недоступна: не настроен GROQ_API_KEY на сервере' });
    }

    const { action, topic, grade_level, duration, group_id, question } = req.body;
    if (!action) return res.status(400).json({ error: 'Поле action обязательно' });

    let systemPrompt = `Ты — AI-ассистент по имени Айгуль, который помогает преподавателю образовательной платформы ЕдуПортал с рутинными задачами: планирование уроков, отчёты, сводки, письма и объявления.
Отвечай на русском языке, структурированно (используй заголовки и списки), по делу, без лишней воды.`;
    let userPrompt = '';

    if (action === 'lesson_plan') {
      if (!topic) return res.status(400).json({ error: 'Укажите тему урока (topic)' });
      userPrompt = `Составь подробный план урока.
Тема: "${topic}".
Уровень/группа: "${grade_level || 'не указан'}".
Длительность: ${duration || 45} минут.
Структура плана: 1) Цели урока, 2) Ключевые понятия, 3) Ход урока по этапам с таймингом (вступление, объяснение, практика, закрепление, подведение итогов), 4) Домашнее задание, 5) Критерии оценивания.`;
    } else if (action === 'report' || action === 'summary') {
      if (!group_id) return res.status(400).json({ error: 'Укажите group_id' });
      const perf = computeGroupPerformance(group_id, req.user.id);
      if (perf.error) return res.status(perf.status || 500).json({ error: perf.error });

      const studentLines = perf.student_summary.map(s =>
        `- ${s.student.full_name || s.student.username}: средний балл ${s.overall_grade_pct ?? '—'}%, посещаемость ${s.overall_attendance_pct ?? '—'}%, пропусков по дедлайну: ${s.missed_deadlines_total}`
      ).join('\n');

      const dataBlock = `Данные по группе "${perf.group.name}":
Средний балл по группе: ${perf.group_avg_grade_pct ?? '—'}%
Средняя посещаемость по группе: ${perf.group_avg_attendance_pct ?? '—'}%
Студентов: ${perf.students_count}, курсов: ${perf.courses_count}
По студентам:
${studentLines || '(нет данных по студентам)'}`;

      userPrompt = action === 'report'
        ? `На основе следующих реальных данных составь официальный отчёт по успеваемости группы для администрации: общий вывод об успеваемости и посещаемости, список студентов в зоне риска (средний балл ниже 60% или посещаемость ниже 70%, или есть пропуски по дедлайну) и рекомендации по улучшению.\n\n${dataBlock}`
        : `На основе следующих реальных данных дай краткую аналитику и 3-5 конкретных рекомендаций преподавателю по этой группе: на что обратить внимание, как поддержать отстающих студентов.\n\n${dataBlock}`;
    } else if (action === 'custom') {
      if (!question) return res.status(400).json({ error: 'Поле question обязательно для action=custom' });
      userPrompt = question;
    } else {
      return res.status(400).json({ error: 'Неизвестный action' });
    }

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${GROQ_API_KEY}`
      },
      body: JSON.stringify({
        model:       'openai/gpt-oss-120b',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user',   content: userPrompt }
        ],
        max_tokens:  1200,
        temperature: 0.6
      })
    });

    const data = await response.json();
    if (data.error) {
      console.error('Groq API error:', data.error);
      return res.status(500).json({ error: data.error.message });
    }
    if (!response.ok || !data.choices || !data.choices[0]) {
      console.error('Groq API bad response:', response.status, JSON.stringify(data));
      return res.status(500).json({ error: 'Groq вернул некорректный ответ' });
    }

    res.json({ answer: data.choices[0].message.content });
  } catch (e) {
    console.error('Teacher AI assistant error:', e);
    res.status(500).json({ error: 'Ошибка AI: ' + e.message });
  }
});

// ─────────────────────────────────────────────
// БИБЛИОТЕКА: книги и подборки (плейлисты)
// ─────────────────────────────────────────────
// Загружать книги и создавать подборки могут: учитель, оператор, админ.
// У каждой книги есть режим доступа:
//   'private' — видят только те, кому явно открыт доступ (студент/группа/учитель) + сам загрузивший + админ/оператор
//   'public'  — видят все авторизованные пользователи
//   'link'    — не отображается в общем списке ни у кого, кроме загрузившего/админа/оператора;
//               открыть книгу может любой, у кого есть прямая ссылка на файл
// ВАЖНО: как и остальные файлы уроков в этом проекте, сам файл отдаётся через статику /uploads
// без проверки токена (по неугадываемому имени файла). Режим доступа управляет тем,
// кто ВИДИТ книгу в библиотеке — а не тем, кто технически может открыть прямую ссылку,
// если она стала кому-то известна. Для 'link' это ожидаемое поведение.

// Возвращает список group_id, в которых состоит студент (для проверки доступа "вся группа")
function studentGroupIds(studentId) {
  return db.prepare('SELECT group_id FROM group_students WHERE student_id = ?').all(studentId).map(r => r.group_id);
}

// Может ли пользователь видеть книгу В ОБЩЕМ СПИСКЕ библиотеки.
// Режим 'link' специально скрывается из общего списка (см. текст в UI:
// "не показывается в общем списке, открыть можно только по прямой ссылке") —
// поэтому здесь он трактуется так же, как 'private', а не как 'public'.
function canSeeLibraryBook(user, book, myGroupIds) {
  if (user.role === 'admin' || user.role === 'operator') return true;
  if (book.uploaded_by === user.id) return true;
  if (book.access_mode === 'public') return true;
  // 'private' и 'link' в общем списке — только по явным правилам доступа
  return hasExplicitLibraryGrant(user, book, myGroupIds);
}

// Может ли пользователь открыть книгу НАПРЯМУЮ (по её id / прямой ссылке).
// БАГ, который был здесь раньше: для режима 'link' эта проверка всегда
// возвращала false, из-за чего книги "только по прямой ссылке" не открывались
// вообще ни у кого, кроме автора загрузки и админа/оператора — сама фича
// "доступ по ссылке" была полностью нерабочей. Теперь 'link' (как и 'public')
// разрешает прямой доступ по id — именно в этом и был смысл этого режима.
function canAccessLibraryBookDirect(user, book, myGroupIds) {
  if (user.role === 'admin' || user.role === 'operator') return true;
  if (book.uploaded_by === user.id) return true;
  if (book.access_mode === 'public' || book.access_mode === 'link') return true;
  return hasExplicitLibraryGrant(user, book, myGroupIds);
}

function hasExplicitLibraryGrant(user, book, myGroupIds) {
  const grants = db.prepare('SELECT target_type, target_id FROM library_book_access WHERE book_id = ?').all(book.id);
  return grants.some(g => {
    if (g.target_type === 'teacher' && user.role === 'teacher' && g.target_id === user.id) return true;
    if (g.target_type === 'student' && user.role === 'student' && g.target_id === user.id) return true;
    if (g.target_type === 'group' && user.role === 'student' && myGroupIds.includes(g.target_id)) return true;
    return false;
  });
}

// GET /api/library/books — список книг (поиск, фильтр по категории, "только мои"), с учётом доступа
app.get('/api/library/books', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    const { search, category, mine } = req.query;
    let sql = `
      SELECT b.*, u.full_name as uploader_name
      FROM library_books b
      JOIN users u ON u.id = b.uploaded_by
      WHERE 1=1
    `;
    const params = [];
    if (search) {
      sql += ` AND (b.title LIKE ? OR b.author LIKE ?)`;
      params.push(`%${search}%`, `%${search}%`);
    }
    if (category) { sql += ` AND b.category = ?`; params.push(category); }
    if (mine === '1') { sql += ` AND b.uploaded_by = ?`; params.push(req.user.id); }
    sql += ` ORDER BY b.created_at DESC`;
    let books = db.prepare(sql).all(...params);

    if (mine !== '1') {
      const myGroupIds = req.user.role === 'student' ? studentGroupIds(req.user.id) : [];
      books = books.filter(b => canSeeLibraryBook(req.user, b, myGroupIds));
    }
    res.json(books);
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/library/books/:id — одна книга (с проверкой доступа)
app.get('/api/library/books/:id', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    const book = db.prepare(`
      SELECT b.*, u.full_name as uploader_name
      FROM library_books b JOIN users u ON u.id = b.uploaded_by
      WHERE b.id = ?
    `).get(req.params.id);
    if (!book) return res.status(404).json({ error: 'Книга не найдена' });
    const myGroupIds = req.user.role === 'student' ? studentGroupIds(req.user.id) : [];
    if (!canAccessLibraryBookDirect(req.user, book, myGroupIds)) return res.status(403).json({ error: 'Нет доступа к этой книге' });
    res.json(book);
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/library/books — загрузить книгу (файл + необязательная обложка)
app.post('/api/library/books', requireAuth('admin', 'operator', 'teacher'), (req, res) => {
  uploadLibraryBook(req, res, (err) => {
    if (err) return res.status(400).json({ error: 'Ошибка загрузки файла: ' + err.message });
    const files = req.files || {};
    if (!files.file || !files.file[0]) return res.status(400).json({ error: 'Файл книги не прикреплён' });
    const sigErr = validateUploadSignatures([...(files.file || []), ...(files.cover || [])]);
    if (sigErr) return res.status(400).json({ error: sigErr });

    try {
      const { title, author, description, category } = req.body;
      const accessMode = ['private', 'public', 'link'].includes(req.body.access_mode) ? req.body.access_mode : 'private';
      if (!title || !title.trim()) {
        deleteFile(files.file[0].filename);
        if (files.cover) deleteFile(files.cover[0].filename);
        return res.status(400).json({ error: 'Укажите название книги' });
      }
      const filePath  = fileUrl(files.file[0].filename);
      const coverPath = files.cover ? fileUrl(files.cover[0].filename) : null;

      const result = db.prepare(`
        INSERT INTO library_books (title, author, description, category, file_path, file_name, cover_path, uploaded_by, access_mode)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        title.trim(), author || null, description || null, category || null,
        filePath, files.file[0].originalname, coverPath, req.user.id, accessMode
      );

      const book = db.prepare('SELECT * FROM library_books WHERE id = ?').get(result.lastInsertRowid);
      res.status(201).json(book);
    } catch (e) {
      sendServerError(res, e);
    }
  });
});

// DELETE /api/library/books/:id — удалить книгу (автор загрузки или админ/оператор)
app.delete('/api/library/books/:id', requireAuth('admin', 'operator', 'teacher'), (req, res) => {
  try {
    const book = db.prepare('SELECT * FROM library_books WHERE id = ?').get(req.params.id);
    if (!book) return res.status(404).json({ error: 'Книга не найдена' });
    if (!['admin', 'operator'].includes(req.user.role) && book.uploaded_by !== req.user.id)
      return res.status(403).json({ error: 'Можно удалять только свои книги' });

    deleteFile(book.file_path);
    deleteFile(book.cover_path);
    db.prepare('DELETE FROM library_books WHERE id = ?').run(book.id);
    res.json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// Проверяет, что пользователь — владелец книги (или админ/оператор); иначе кидает ответ 403/404 и возвращает null
function requireBookOwner(req, res) {
  const book = db.prepare('SELECT * FROM library_books WHERE id = ?').get(req.params.id);
  if (!book) { res.status(404).json({ error: 'Книга не найдена' }); return null; }
  if (!['admin', 'operator'].includes(req.user.role) && book.uploaded_by !== req.user.id) {
    res.status(403).json({ error: 'Управлять доступом может только автор загрузки' });
    return null;
  }
  return book;
}

// GET /api/library/books/:id/access — режим доступа + список правил (для панели управления у владельца)
app.get('/api/library/books/:id/access', requireAuth('admin', 'operator', 'teacher'), (req, res) => {
  try {
    const book = requireBookOwner(req, res);
    if (!book) return;
    const grants = db.prepare(`
      SELECT a.id, a.target_type, a.target_id,
             CASE a.target_type
               WHEN 'group' THEN g.name
               ELSE u.full_name
             END as target_name
      FROM library_book_access a
      LEFT JOIN users  u ON a.target_type IN ('student','teacher') AND u.id = a.target_id
      LEFT JOIN groups g ON a.target_type = 'group' AND g.id = a.target_id
      WHERE a.book_id = ?
      ORDER BY a.created_at DESC
    `).all(book.id);
    res.json({ access_mode: book.access_mode, grants });
  } catch (e) {
    sendServerError(res, e);
  }
});

// PUT /api/library/books/:id/access-mode — сменить режим (private / public / link)
app.put('/api/library/books/:id/access-mode', requireAuth('admin', 'operator', 'teacher'), (req, res) => {
  try {
    const book = requireBookOwner(req, res);
    if (!book) return;
    const { access_mode } = req.body;
    if (!['private', 'public', 'link'].includes(access_mode))
      return res.status(400).json({ error: 'Некорректный режим доступа' });
    db.prepare('UPDATE library_books SET access_mode = ? WHERE id = ?').run(access_mode, book.id);
    res.json({ success: true, access_mode });
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/library/books/:id/access — выдать доступ студенту / группе / учителю
app.post('/api/library/books/:id/access', requireAuth('admin', 'operator', 'teacher'), (req, res) => {
  try {
    const book = requireBookOwner(req, res);
    if (!book) return;
    const { target_type, target_id } = req.body;
    if (!['student', 'teacher', 'group'].includes(target_type))
      return res.status(400).json({ error: 'Некорректный тип получателя доступа' });
    const id = parseInt(target_id);
    if (!id) return res.status(400).json({ error: 'Не указан получатель доступа' });

    if (target_type === 'group') {
      const group = db.prepare('SELECT id FROM groups WHERE id = ?').get(id);
      if (!group) return res.status(404).json({ error: 'Группа не найдена' });
    } else {
      const user = db.prepare('SELECT id, role FROM users WHERE id = ?').get(id);
      if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
      if (user.role !== target_type) return res.status(400).json({ error: `Пользователь не является ролью "${target_type}"` });
    }

    db.prepare(`
      INSERT OR IGNORE INTO library_book_access (book_id, target_type, target_id, granted_by)
      VALUES (?, ?, ?, ?)
    `).run(book.id, target_type, id, req.user.id);

    res.status(201).json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// DELETE /api/library/books/:id/access/:grantId — отозвать конкретное правило доступа
app.delete('/api/library/books/:id/access/:grantId', requireAuth('admin', 'operator', 'teacher'), (req, res) => {
  try {
    const book = requireBookOwner(req, res);
    if (!book) return;
    db.prepare('DELETE FROM library_book_access WHERE id = ? AND book_id = ?').run(req.params.grantId, book.id);
    res.json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/library/playlists — список подборок (плейлистов библиотеки)
app.get('/api/library/playlists', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT p.*, u.full_name as owner_name,
             (SELECT COUNT(*) FROM library_playlist_items i WHERE i.playlist_id = p.id) as book_count
      FROM library_playlists p
      JOIN users u ON u.id = p.owner_id
      ORDER BY p.created_at DESC
    `).all();
    res.json(rows);
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/library/playlists — создать подборку
app.post('/api/library/playlists', requireAuth('admin', 'operator', 'teacher'), (req, res) => {
  try {
    const { title, description } = req.body;
    if (!title || !title.trim()) return res.status(400).json({ error: 'Укажите название подборки' });
    const result = db.prepare(`
      INSERT INTO library_playlists (title, description, owner_id) VALUES (?, ?, ?)
    `).run(title.trim(), description || null, req.user.id);
    res.status(201).json(db.prepare('SELECT * FROM library_playlists WHERE id = ?').get(result.lastInsertRowid));
  } catch (e) {
    sendServerError(res, e);
  }
});

// GET /api/library/playlists/:id — подборка с книгами внутри (книги фильтруются по доступу)
app.get('/api/library/playlists/:id', requireAuth('admin', 'operator', 'teacher', 'student'), (req, res) => {
  try {
    const playlist = db.prepare('SELECT * FROM library_playlists WHERE id = ?').get(req.params.id);
    if (!playlist) return res.status(404).json({ error: 'Подборка не найдена' });
    let books = db.prepare(`
      SELECT b.*, i.order_index
      FROM library_playlist_items i
      JOIN library_books b ON b.id = i.book_id
      WHERE i.playlist_id = ?
      ORDER BY i.order_index ASC, i.added_at ASC
    `).all(playlist.id);
    const myGroupIds = req.user.role === 'student' ? studentGroupIds(req.user.id) : [];
    playlist.books = books.filter(b => canSeeLibraryBook(req.user, b, myGroupIds));
    res.json(playlist);
  } catch (e) {
    sendServerError(res, e);
  }
});


// PUT /api/library/playlists/:id — переименовать подборку (владелец/админ)
app.put('/api/library/playlists/:id', requireAuth('admin', 'operator', 'teacher'), (req, res) => {
  try {
    const playlist = db.prepare('SELECT * FROM library_playlists WHERE id = ?').get(req.params.id);
    if (!playlist) return res.status(404).json({ error: 'Подборка не найдена' });
    if (req.user.role !== 'admin' && playlist.owner_id !== req.user.id)
      return res.status(403).json({ error: 'Можно редактировать только свои подборки' });
    const { title, description } = req.body;
    db.prepare('UPDATE library_playlists SET title = ?, description = ? WHERE id = ?')
      .run(title || playlist.title, description ?? playlist.description, playlist.id);
    res.json(db.prepare('SELECT * FROM library_playlists WHERE id = ?').get(playlist.id));
  } catch (e) {
    sendServerError(res, e);
  }
});

// DELETE /api/library/playlists/:id — удалить подборку (владелец/админ)
app.delete('/api/library/playlists/:id', requireAuth('admin', 'operator', 'teacher'), (req, res) => {
  try {
    const playlist = db.prepare('SELECT * FROM library_playlists WHERE id = ?').get(req.params.id);
    if (!playlist) return res.status(404).json({ error: 'Подборка не найдена' });
    if (req.user.role !== 'admin' && playlist.owner_id !== req.user.id)
      return res.status(403).json({ error: 'Можно удалять только свои подборки' });
    db.prepare('DELETE FROM library_playlists WHERE id = ?').run(playlist.id);
    res.json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// POST /api/library/playlists/:id/books — добавить книгу в подборку
app.post('/api/library/playlists/:id/books', requireAuth('admin', 'operator', 'teacher'), (req, res) => {
  try {
    const playlist = db.prepare('SELECT * FROM library_playlists WHERE id = ?').get(req.params.id);
    if (!playlist) return res.status(404).json({ error: 'Подборка не найдена' });
    if (req.user.role !== 'admin' && playlist.owner_id !== req.user.id)
      return res.status(403).json({ error: 'Можно редактировать только свои подборки' });
    const { book_id } = req.body;
    const book = db.prepare('SELECT * FROM library_books WHERE id = ?').get(book_id);
    if (!book) return res.status(404).json({ error: 'Книга не найдена' });

    const maxOrder = db.prepare('SELECT MAX(order_index) as m FROM library_playlist_items WHERE playlist_id = ?').get(playlist.id).m;
    db.prepare(`
      INSERT OR IGNORE INTO library_playlist_items (playlist_id, book_id, order_index) VALUES (?, ?, ?)
    `).run(playlist.id, book_id, (maxOrder ?? -1) + 1);

    res.status(201).json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// DELETE /api/library/playlists/:id/books/:bookId — убрать книгу из подборки
app.delete('/api/library/playlists/:id/books/:bookId', requireAuth('admin', 'operator', 'teacher'), (req, res) => {
  try {
    const playlist = db.prepare('SELECT * FROM library_playlists WHERE id = ?').get(req.params.id);
    if (!playlist) return res.status(404).json({ error: 'Подборка не найдена' });
    if (req.user.role !== 'admin' && playlist.owner_id !== req.user.id)
      return res.status(403).json({ error: 'Можно редактировать только свои подборки' });
    db.prepare('DELETE FROM library_playlist_items WHERE playlist_id = ? AND book_id = ?')
      .run(playlist.id, req.params.bookId);
    res.json({ success: true });
  } catch (e) {
    sendServerError(res, e);
  }
});

// Простой health-check без авторизации — чтобы:
//  1) внешний мониторинг (UptimeRobot, healthchecks.io и т.п.) мог
//     проверять, что сервер жив, и присылать уведомление, если он упал;
//  2) на бесплатных хостингах, где сервер "засыпает" при простое, можно
//     было настроить периодический пинг сюда, чтобы он не засыпал.
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// ─────────────────────────────────────────────
// ОТДАЁМ FRONTEND — index.html по умолчанию (должен быть последним роутом)
// ─────────────────────────────────────────────
app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send('Frontend не найден. Убедитесь что папка public существует.');
  }
});

// ─────────────────────────────────────────────
// ВИДЕОЗВОНКИ — WebSocket-сигналинг (/ws/video)
// ─────────────────────────────────────────────
// Сервер только пересылает сигнальные сообщения (SDP/ICE) между участниками
// и хранит состояние комнаты — сам медиапоток через сервер не проходит
// (чистый WebRTC, без SFU/MCU).
const httpServer = http.createServer(app);

// По умолчанию в Node 18+ у HTTP-сервера есть requestTimeout (5 минут) и
// headersTimeout (60 секунд). На localhost файл передаётся почти мгновенно,
// поэтому лимиты незаметны. А вот через туннель (ngrok и т.п.) канал часто
// намного уже — большое видео/книга может просто не успеть загрузиться за
// 5 минут, и Node обрывает соединение посреди загрузки. Со стороны браузера
// это выглядит как "не получается загрузить/опубликовать файл", хотя на
// самом деле сервер сам разорвал соединение по таймауту. Снимаем это
// ограничение для загрузок — файлы всё равно ограничены по размеру через
// multer (limits.fileSize), так что зависшие запросы не копятся бесконечно.
httpServer.requestTimeout   = 0;        // без ограничения по времени на весь запрос
httpServer.headersTimeout   = 120000;   // 2 минуты на получение заголовков (было 60с — мало для медленных туннелей)
httpServer.keepAliveTimeout = 65000;    // чуть больше типичных 60с таймаутов прокси (ngrok и т.п.), чтобы не рвать keep-alive раньше туннеля
const wss = new WebSocket.Server({ server: httpServer, path: '/ws/video' });

function wsSend(ws, msg) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

function wsSendError(ws, error) {
  wsSend(ws, { type: 'error', error });
}

// Рассылает сообщение всем участникам комнаты (кроме excludeUserId, если задан)
function broadcastToRoom(room, msg, excludeUserId = null) {
  for (const [uid, p] of room.participants) {
    if (uid === excludeUserId) continue;
    wsSend(p.ws, msg);
  }
}

function findRoomOfUser(userId) {
  for (const room of videoRooms.values()) {
    if (room.participants.has(userId)) return room;
  }
  return null;
}

// Убирает пользователя из комнаты (leave/disconnect), фиксирует в БД,
// уведомляет остальных. Если ушёл учитель — завершает звонок целиком.
function removeParticipant(room, userId, { endIfTeacher = true } = {}) {
  const p = room.participants.get(userId);
  if (!p) return;
  room.participants.delete(userId);
  try {
    db.prepare(`UPDATE video_room_participants SET left_at = CURRENT_TIMESTAMP
                WHERE room_id = ? AND user_id = ? AND left_at IS NULL`).run(room.id, userId);
  } catch (_) {}
  broadcastToRoom(room, { type: 'participant-left', room_id: room.id, user_id: userId });

  if (endIfTeacher && userId === room.teacherId) {
    endRoom(room, 'teacher-disconnected');
  }
}

function endRoom(room, reason = 'ended') {
  broadcastToRoom(room, { type: 'room-ended', room_id: room.id, reason });
  try {
    db.prepare(`UPDATE video_room_participants SET left_at = CURRENT_TIMESTAMP
                WHERE room_id = ? AND left_at IS NULL`).run(room.id);
    db.prepare(`UPDATE video_rooms SET status = 'ended', ended_at = CURRENT_TIMESTAMP WHERE id = ?`).run(room.id);
  } catch (_) {}
  videoRooms.delete(room.id);
}

wss.on('connection', (ws) => {
  ws.userId = null;
  ws.role = null;
  ws.fullName = null;
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return wsSendError(ws, 'Некорректный JSON'); }

    // Первое сообщение обязано быть аутентификацией
    if (!ws.userId) {
      if (msg.type !== 'auth' || !msg.token) return wsSendError(ws, 'Требуется аутентификация');
      try {
        const payload = jwt.verify(msg.token, JWT_SECRET);
        if (!['teacher', 'student'].includes(payload.role)) {
          wsSendError(ws, 'Роль не поддерживает видеозвонки');
          return ws.close();
        }
        ws.userId = payload.id;
        ws.role = payload.role;
        ws.fullName = payload.full_name || payload.username;
        return wsSend(ws, { type: 'auth-ok', user_id: ws.userId, role: ws.role });
      } catch {
        wsSendError(ws, 'Токен недействителен');
        return ws.close();
      }
    }

    try {
      handleVideoMessage(ws, msg);
    } catch (e) {
      wsSendError(ws, e.message || 'Внутренняя ошибка');
    }
  });

  ws.on('close', () => {
    if (!ws.userId) return;
    const room = findRoomOfUser(ws.userId);
    if (room) removeParticipant(room, ws.userId);
  });
});

// Пинг раз в 30с — вычищаем мёртвые соединения (обрыв сети/сон вкладки)
const wsHeartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      if (ws.userId) {
        const room = findRoomOfUser(ws.userId);
        if (room) removeParticipant(room, ws.userId);
      }
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);
httpServer.on('close', () => clearInterval(wsHeartbeat));

function handleVideoMessage(ws, msg) {
  const { type } = msg;

  if (type === 'create-room') {
    if (ws.role !== 'teacher') return wsSendError(ws, 'Только учитель может начать звонок');
    const groupIds = Array.isArray(msg.group_ids) ? msg.group_ids.map(Number).filter(Boolean) : [];
    if (!groupIds.length) return wsSendError(ws, 'Нужно выбрать хотя бы одну группу');
    for (const gid of groupIds) {
      if (!teacherHasGroupAccess(ws.userId, gid)) return wsSendError(ws, 'Нет доступа к одной из групп');
    }
    // Если у учителя уже есть активный звонок — завершаем его перед новым
    const existing = db.prepare(`SELECT id FROM video_rooms WHERE teacher_id = ? AND status = 'active'`).get(ws.userId);
    if (existing) {
      const oldRoom = videoRooms.get(existing.id);
      if (oldRoom) endRoom(oldRoom, 'replaced');
      else db.prepare(`UPDATE video_rooms SET status='ended', ended_at=CURRENT_TIMESTAMP WHERE id=?`).run(existing.id);
    }

    const info = db.prepare('INSERT INTO video_rooms (teacher_id, title) VALUES (?, ?)')
      .run(ws.userId, msg.title || null);
    const roomId = info.lastInsertRowid;
    const insertGroup = db.prepare('INSERT INTO video_room_groups (room_id, group_id) VALUES (?, ?)');
    for (const gid of groupIds) insertGroup.run(roomId, gid);

    const room = { id: roomId, teacherId: ws.userId, title: msg.title || null, groupIds: new Set(groupIds), participants: new Map() };
    videoRooms.set(roomId, room);

    joinRoomInternal(room, ws);
    return wsSend(ws, { type: 'room-created', room_id: roomId, group_ids: groupIds });
  }

  if (type === 'join-room') {
    const room = videoRooms.get(Number(msg.room_id));
    if (!room) return wsSendError(ws, 'Звонок не найден или завершён');
    if (ws.role === 'student' && !studentInAnyGroup(ws.userId, [...room.groupIds])) {
      return wsSendError(ws, 'Нет доступа к этому звонку');
    }
    if (ws.role === 'teacher' && ws.userId !== room.teacherId) {
      return wsSendError(ws, 'Это не ваш звонок');
    }
    joinRoomInternal(room, ws);
    return;
  }

  // Остальные типы сообщений требуют, чтобы пользователь уже состоял в комнате
  const room = videoRooms.get(Number(msg.room_id));
  if (!room || !room.participants.has(ws.userId)) return wsSendError(ws, 'Вы не в этом звонке');

  switch (type) {
    case 'leave-room':
      removeParticipant(room, ws.userId, { endIfTeacher: false });
      if (ws.userId === room.teacherId) endRoom(room, 'teacher-left');
      break;

    case 'end-room':
      if (ws.userId !== room.teacherId) return wsSendError(ws, 'Только учитель может завершить звонок');
      endRoom(room, 'ended');
      break;

    // Пересылка SDP/ICE один-в-один; сервер содержимое не разбирает
    case 'offer':
    case 'answer':
    case 'ice-candidate': {
      const target = room.participants.get(Number(msg.to_user_id));
      if (!target) return wsSendError(ws, 'Получатель не в звонке');
      wsSend(target.ws, { type, room_id: room.id, from_user_id: ws.userId, payload: msg.payload });
      break;
    }

    case 'raise-hand':
    case 'lower-hand': {
      if (ws.role !== 'student') return;
      const raised = type === 'raise-hand';
      const p = room.participants.get(ws.userId);
      p.handRaised = raised;
      db.prepare(`UPDATE video_room_participants SET hand_raised = ?, hand_raised_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE hand_raised_at END
                  WHERE room_id = ? AND user_id = ? AND left_at IS NULL`).run(raised ? 1 : 0, raised ? 1 : 0, room.id, ws.userId);
      broadcastToRoom(room, { type: raised ? 'hand-raised' : 'hand-lowered', room_id: room.id, user_id: ws.userId });
      break;
    }

    case 'screen-share-start': {
      const scope = msg.scope === 'teacher-only' ? 'teacher-only' : 'all';
      const p = room.participants.get(ws.userId);
      p.screenSharing = true;
      p.screenScope = scope;
      broadcastToRoom(room, { type: 'screen-share-started', room_id: room.id, user_id: ws.userId, scope }, ws.userId);
      break;
    }

    case 'screen-share-stop': {
      const p = room.participants.get(ws.userId);
      p.screenSharing = false;
      p.screenScope = null;
      broadcastToRoom(room, { type: 'screen-share-stopped', room_id: room.id, user_id: ws.userId }, ws.userId);
      break;
    }

    // Учитель приглушает микрофон/камеру одного, нескольких или всей группы.
    // Это НЕ аппаратный форс-мьют: клиент студента сам обязан выполнить
    // track.enabled=false — модель работает при доверенном клиенте, как
    // принято для учебных платформ на чистом WebRTC без SFU.
    case 'mute-request': {
      if (ws.role !== 'teacher') return wsSendError(ws, 'Только учитель может управлять микрофоном/камерой');
      const kind = msg.kind === 'cam' ? 'cam' : 'mic';
      const enabled = !!msg.enabled;
      const targetIds = Array.isArray(msg.target_user_ids) ? msg.target_user_ids.map(Number) : [];
      const col = kind === 'cam' ? 'cam_enabled' : 'mic_enabled';
      for (const uid of targetIds) {
        const p = room.participants.get(uid);
        if (!p || p.role !== 'student') continue;
        if (kind === 'cam') p.camEnabled = enabled; else p.micEnabled = enabled;
        db.prepare(`UPDATE video_room_participants SET ${col} = ? WHERE room_id = ? AND user_id = ? AND left_at IS NULL`)
          .run(enabled ? 1 : 0, room.id, uid);
        wsSend(p.ws, { type: 'force-mute', room_id: room.id, kind, enabled });
      }
      break;
    }

    default:
      wsSendError(ws, `Неизвестный тип сообщения: ${type}`);
  }
}

function joinRoomInternal(room, ws) {
  // Если это переподключение — просто обновляем ws-ссылку
  const existing = room.participants.get(ws.userId);
  const participant = existing || {
    ws, role: ws.role, fullName: ws.fullName,
    micEnabled: true, camEnabled: true, handRaised: false,
    screenSharing: false, screenScope: null
  };
  participant.ws = ws;
  room.participants.set(ws.userId, participant);

  try {
    const already = db.prepare(`SELECT id FROM video_room_participants WHERE room_id = ? AND user_id = ? AND left_at IS NULL`)
      .get(room.id, ws.userId);
    if (!already) {
      db.prepare('INSERT INTO video_room_participants (room_id, user_id) VALUES (?, ?)').run(room.id, ws.userId);
    }
  } catch (_) {}

  // Список текущих участников — только новоприбывшему, чтобы он мог
  // инициировать WebRTC-соединения (для студента — только с учителем)
  const existingList = [...room.participants.entries()]
    .filter(([uid]) => uid !== ws.userId)
    .map(([uid, p]) => ({ user_id: uid, role: p.role, full_name: p.fullName, hand_raised: p.handRaised }));
  wsSend(ws, {
    type: 'room-state', room_id: room.id, teacher_id: room.teacherId,
    title: room.title, participants: existingList
  });

  broadcastToRoom(room, {
    type: 'participant-joined', room_id: room.id, user_id: ws.userId,
    role: ws.role, full_name: ws.fullName
  }, ws.userId);
}

// ─────────────────────────────────────────────
// ЗАПУСК СЕРВЕРА
// ─────────────────────────────────────────────
r2Storage.restoreUploadsFromR2(UPLOADS).finally(() => {
  httpServer.listen(PORT, () => {
    console.log('');
    console.log('╔════════════════════════════════════════╗');
    console.log('║        ЕдуПортал — сервер запущен      ║');
    console.log('╠════════════════════════════════════════╣');
    console.log(`║  Адрес:  http://localhost:${PORT}          ║`);
    console.log('║  Логин:  admin                          ║');
    console.log('║  Пароль: admin123                       ║');
    console.log('╚════════════════════════════════════════╝');
    console.log('');
  });
});
