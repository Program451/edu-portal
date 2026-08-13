// ─────────────────────────────────────────────────────────────────────────
// r2-storage.js — резервное копирование папки uploads/ в Cloudflare R2
//
// Для больших видео используем ReadStream вместо fs.readFileSync(), чтобы
// не блокировать event loop Node.js и не создавать гигантский Buffer в памяти.
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

function contentTypeFor(filename) {
  const ext = path.extname(filename).toLowerCase();
  const types = {
    '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime',
    '.m4v': 'video/x-m4v', '.mkv': 'video/x-matroska', '.avi': 'video/x-msvideo',
    '.pdf': 'application/pdf', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.png': 'image/png', '.webp': 'image/webp', '.gif': 'image/gif',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.ppt': 'application/vnd.ms-powerpoint',
    '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    '.xls': 'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.txt': 'text/plain; charset=utf-8', '.epub': 'application/epub+zip',
    '.fb2': 'application/xml', '.rtf': 'application/rtf'
  };
  return types[ext] || 'application/octet-stream';
}

// Fire-and-forget: загрузка в R2 идёт потоково и не блокирует event loop.
async function uploadFileToR2(localPath, key) {
  if (!enabled) return;
  const body = fs.createReadStream(localPath);
  body.on('error', err => console.error(`[r2-storage] Ошибка чтения ${key}:`, err.message));
  try {
    await s3.client.send(new s3.PutObjectCommand({
      Bucket: R2_BUCKET,
      Key: `uploads/${key}`,
      Body: body,
      ContentType: contentTypeFor(key)
    }));
    console.log(`[r2-storage] Файл сохранён: ${key}`);
  } catch (err) {
    console.error(`[r2-storage] Не удалось сохранить резервную копию ${key}:`, err.message);
  }
}

// Восстановление из R2 также выполняется потоково, чтобы большой видеофайл
// не собирался целиком в RAM при старте сервера.
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
        if (fs.existsSync(localPath)) continue;
        const res = await s3.client.send(new s3.GetObjectCommand({ Bucket: R2_BUCKET, Key: obj.Key }));
        const out = fs.createWriteStream(localPath);
        await new Promise((resolve, reject) => {
          res.Body.pipe(out);
          res.Body.on('error', reject);
          out.on('finish', resolve);
          out.on('error', reject);
        });
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
