// ─────────────────────────────────────────────────────────────────────────
// r2-storage.js — резервное копирование папки uploads/ в Cloudflare R2
//
// Зачем: на бесплатном тарифе Render локальный диск НЕ сохраняется между
// перезапусками сервера. База данных (database.db) уже защищена через
// Litestream (см. litestream.yml). Этот модуль решает ту же проблему для
// загруженных пользователями файлов (домашки, видео уроков, книги и т.д.):
//   - при каждой успешной загрузке файл асинхронно копируется в R2
//   - при старте сервера все файлы, которых нет локально, скачиваются из R2
//
// Если переменные окружения R2_* не заданы — модуль просто ничего не делает
// (удобно для локальной разработки, где перезапуски не проблема).
// ─────────────────────────────────────────────────────────────────────────

const fs = require('fs');
const path = require('path');

const R2_BUCKET     = process.env.R2_BUCKET;
const R2_ENDPOINT   = process.env.R2_ENDPOINT;
const R2_ACCESS_KEY = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_KEY = process.env.R2_SECRET_ACCESS_KEY;

const enabled = !!(R2_BUCKET && R2_ENDPOINT && R2_ACCESS_KEY && R2_SECRET_KEY);

let s3 = null;
if (enabled) {
  // Ленивая загрузка, чтобы @aws-sdk/client-s3 не был обязателен, если R2 не используется
  const { S3Client, PutObjectCommand, ListObjectsV2Command, GetObjectCommand } = require('@aws-sdk/client-s3');
  s3 = {
    client: new S3Client({
      region: 'auto',
      endpoint: R2_ENDPOINT,
      credentials: { accessKeyId: R2_ACCESS_KEY, secretAccessKey: R2_SECRET_KEY }
    }),
    PutObjectCommand, ListObjectsV2Command, GetObjectCommand
  };
  console.log('[r2-storage] Резервное копирование uploads/ в Cloudflare R2 включено.');
} else {
  console.log('[r2-storage] R2 не настроен (нет переменных R2_*) — резервное копирование файлов выключено.');
}

// Загружает один файл в R2 (fire-and-forget, вызывающий код не должен ждать)
async function uploadFileToR2(localPath, key) {
  if (!enabled) return;
  try {
    const body = fs.readFileSync(localPath);
    await s3.client.send(new s3.PutObjectCommand({
      Bucket: R2_BUCKET,
      Key: `uploads/${key}`,
      Body: body
    }));
  } catch (err) {
    console.error(`[r2-storage] Не удалось сохранить резервную копию файла ${key}:`, err.message);
  }
}

// Скачивает из R2 все файлы, которых ещё нет в локальной папке uploads/
// Вызывается один раз при старте сервера.
async function restoreUploadsFromR2(uploadsDir) {
  if (!enabled) return;
  try {
    let continuationToken;
    let restored = 0;
    do {
      const list = await s3.client.send(new s3.ListObjectsV2Command({
        Bucket: R2_BUCKET,
        Prefix: 'uploads/',
        ContinuationToken: continuationToken
      }));
      for (const obj of list.Contents || []) {
        const filename = obj.Key.replace(/^uploads\//, '');
        if (!filename) continue;
        const localPath = path.join(uploadsDir, filename);
        if (fs.existsSync(localPath)) continue; // уже есть локально
        const res = await s3.client.send(new s3.GetObjectCommand({ Bucket: R2_BUCKET, Key: obj.Key }));
        const chunks = [];
        for await (const chunk of res.Body) chunks.push(chunk);
        fs.writeFileSync(localPath, Buffer.concat(chunks));
        restored++;
      }
      continuationToken = list.IsTruncated ? list.NextContinuationToken : undefined;
    } while (continuationToken);
    if (restored > 0) console.log(`[r2-storage] Восстановлено файлов из R2: ${restored}`);
  } catch (err) {
    console.error('[r2-storage] Не удалось восстановить файлы из R2:', err.message);
  }
}

module.exports = { enabled, uploadFileToR2, restoreUploadsFromR2 };
