'use strict';
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');
const r2Storage = require('../r2-storage');
const { UPLOADS } = require('../config');

// ─────────────────────────────────────────────
// MULTER — настройка загрузки файлов
// ─────────────────────────────────────────────
function makeStorage() {
  const diskEngine = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS),
    filename:    (req, file, cb) => {
      const ext  = path.extname(file.originalname);
      const name = Date.now() + '_' + Math.round(Math.random() * 1e6) + ext;
      cb(null, name);
    }
  });
  // Оборачиваем стандартный diskStorage: после успешной записи на диск файл
  // асинхронно копируется в Cloudflare R2 (см. r2-storage.js), чтобы не
  // потеряться при перезапуске бесплатного сервера на Render. Если R2 не
  // настроен, r2Storage.uploadFileToR2 просто ничего не делает.
  return {
    _handleFile(req, file, cb) {
      diskEngine._handleFile(req, file, (err, info) => {
        if (err) return cb(err);
        r2Storage.uploadFileToR2(info.path, info.filename)
          .catch(e => console.error('[r2-storage] Ошибка фоновой загрузки:', e.message));
        cb(null, info);
      });
    },
    _removeFile(req, file, cb) {
      diskEngine._removeFile(req, file, cb);
    }
  };
}

// Доп. проверка содержимого файла по "магическим байтам" (сигнатуре), а не
// только по расширению из имени файла. fileFilter выше уже отсекает
// неподходящие расширения, но расширение — это просто текст в имени файла,
// его может подделать сам браузер/клиент. Эта проверка читает первые байты
// уже сохранённого файла и убеждается, что они соответствуют заявленному
// типу — защищает от файла, который выглядит как .jpg/.png/.pdf по имени,
// но на самом деле содержит что-то другое.
const FILE_SIGNATURES = {
  '.jpg':  [[0xFF, 0xD8, 0xFF]],
  '.jpeg': [[0xFF, 0xD8, 0xFF]],
  '.png':  [[0x89, 0x50, 0x4E, 0x47]],
  '.gif':  [[0x47, 0x49, 0x46, 0x38]],
  '.webp': [[0x52, 0x49, 0x46, 0x46]], // 'RIFF' (WEBP чуть дальше в файле)
  '.pdf':  [[0x25, 0x50, 0x44, 0x46]]  // '%PDF'
};
function checkFileSignature(filePath, ext) {
  const sigs = FILE_SIGNATURES[ext.toLowerCase()];
  if (!sigs) return true; // для форматов без простой сигнатуры (docx/epub/txt и т.п.) проверку не делаем
  let head;
  try {
    const fd = fs.openSync(filePath, 'r');
    head = Buffer.alloc(12);
    fs.readSync(fd, head, 0, 12, 0);
    fs.closeSync(fd);
  } catch {
    return true; // не смогли прочитать — не блокируем, дальше по коду файл всё равно попытаются открыть
  }
  return sigs.some(sig => sig.every((byte, i) => head[i] === byte));
}
// Проверяет список файлов Multer (req.files/req.file) по сигнатуре и удаляет
// с диска те, что не совпали с заявленным расширением. Возвращает текст
// ошибки (для ответа клиенту) или null, если всё ок.
function validateUploadSignatures(files) {
  for (const file of files) {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!checkFileSignature(file.path, ext)) {
      try { fs.unlinkSync(file.path); } catch {}
      return `Файл "${file.originalname}" повреждён или не является файлом формата ${ext} (содержимое не совпадает с расширением)`;
    }
  }
  return null;
}

// Загрузка файлов урока (видео 2D, VR, материал)
// Раньше здесь не было fileFilter вообще — можно было загрузить файл с любым
// расширением (включая .html/.svg/.js), а он потом отдаётся как материал урока
// по прямой ссылке из /uploads. Открытый в браузере .html/.svg с телом
// пользователя выполнился бы в контексте нашего сайта (хранимый XSS с
// доступом к sessionStorage, где лежит JWT). Ограничиваем расширения по типу поля.
const uploadLesson = multer({
  storage: makeStorage(),
  limits:  { fileSize: 2 * 1024 * 1024 * 1024 }, // 2GB
  fileFilter: (req, file, cb) => {
    const videoExt    = ['.mp4', '.webm', '.mov', '.mkv', '.avi', '.m4v'];
    const materialExt = ['.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.txt', '.jpg', '.jpeg', '.png', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if ((file.fieldname === 'video_2d' || file.fieldname === 'video_vr') && !videoExt.includes(ext)) {
      return cb(new Error(`Видео должно быть в формате: ${videoExt.join(', ')} (получено: ${ext || 'без расширения'})`));
    }
    if (file.fieldname === 'material' && !materialExt.includes(ext)) {
      return cb(new Error(`Материал должен быть в формате: ${materialExt.join(', ')} (получено: ${ext || 'без расширения'})`));
    }
    cb(null, true);
  }
}).fields([
  { name: 'video_2d',  maxCount: 1 },
  { name: 'video_vr',  maxCount: 1 },
  { name: 'material',  maxCount: 1 }
]);

// Загрузка домашнего задания (PDF / Word)
const uploadHomework = multer({
  storage: makeStorage(),
  limits:  { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.pdf', '.doc', '.docx'];
    const ext = path.extname(file.originalname).toLowerCase();
    // БАГ (найден и исправлен): cb(null, false) молча отбрасывал файл с
    // неподходящим расширением, и сервер потом отвечал "Файл не прикреплён" —
    // как будто студент вообще ничего не выбрал. Теперь сразу понятная ошибка.
    if (!allowed.includes(ext)) return cb(new Error(`Неподдерживаемый формат файла (${ext || 'без расширения'}). Разрешены: ${allowed.join(', ')}`));
    cb(null, true);
  }
}).single('file');

// Загрузка изображений для тестов
const uploadQuiz = multer({
  storage: makeStorage(),
  limits:  { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    // Та же проблема: раньше неподходящий файл отбрасывался молча.
    if (!allowed.includes(ext)) return cb(new Error(`Изображение должно быть в формате: ${allowed.join(', ')} (получено: ${ext || 'без расширения'})`));
    cb(null, true);
  }
}).any();

// Загрузка книг в библиотеку (сам файл книги + необязательная обложка)
const uploadLibraryBook = multer({
  storage: makeStorage(),
  limits:  { fileSize: 500 * 1024 * 1024 }, // 500MB
  fileFilter: (req, file, cb) => {
    const bookExt  = ['.pdf', '.doc', '.docx', '.epub', '.fb2', '.txt', '.rtf'];
    const imageExt = ['.jpg', '.jpeg', '.png', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    // БАГ, который был здесь раньше: cb(null, false) молча отбрасывал файл
    // с неподходящим расширением, а сервер потом отвечал непонятным
    // "Файл книги не прикреплён" — как будто файл вообще не выбирали.
    // Теперь при неверном формате возвращаем внятную ошибку сразу.
    if (file.fieldname === 'cover') {
      if (!imageExt.includes(ext)) return cb(new Error(`Обложка должна быть изображением (${imageExt.join(', ')})`));
      return cb(null, true);
    }
    if (!bookExt.includes(ext)) return cb(new Error(`Неподдерживаемый формат файла книги (${ext || 'без расширения'}). Разрешены: ${bookExt.join(', ')}`));
    cb(null, true);
  }
}).fields([
  { name: 'file',  maxCount: 1 },
  { name: 'cover', maxCount: 1 }
]);

// Импорт пользователей из Excel/CSV — файл не нужно сохранять на диск, только распарсить
const uploadImport = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.xlsx', '.xls', '.csv'];
    const ext = path.extname(file.originalname).toLowerCase();
    // Та же проблема: раньше неподходящий файл отбрасывался молча, и админ
    // видел невнятную ошибку "файл не выбран" вместо причины.
    if (!allowed.includes(ext)) return cb(new Error(`Неподдерживаемый формат файла (${ext || 'без расширения'}). Разрешены: ${allowed.join(', ')}`));
    cb(null, true);
  }
}).single('file');

module.exports = {
  uploadLesson,
  uploadHomework,
  uploadQuiz,
  uploadLibraryBook,
  uploadImport,
  validateUploadSignatures
};
