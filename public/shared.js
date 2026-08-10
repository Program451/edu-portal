// ─────────────────────────────────────────────
// ОБЩИЕ ХЕЛПЕРЫ: красивая drag-and-drop зона для <input type="file">
// вместо стандартной серой узкой кнопки браузера.
//
// Разметка (см. .file-drop-zone / .file-selected в shared.css):
//   <div class="file-drop-zone" id="myDrop"
//        ondragover="onDragOver(event,'myDrop')"
//        ondragleave="onDragLeave('myDrop')"
//        ondrop="onDrop(event,'myFile','myDrop')">
//     <input type="file" id="myFile" onchange="onFileSelected('myFile','myDrop','mySel')">
//     <span class="drop-icon">📎</span>
//     <div class="drop-title">Перетащите файл или нажмите для выбора</div>
//     <div class="drop-hint">Подсказка о формате/размере</div>
//   </div>
//   <div class="file-selected hidden" id="mySel">
//     <span>📎</span>
//     <span class="file-name" id="mySel-name"></span>
//     <button class="btn-remove" onclick="clearFile('myFile','myDrop','mySel')">✕</button>
//   </div>
//
// Эти же функции уже используются в teacher.html и student.html —
// вынесены сюда, чтобы не копипастить в admin.html/operator.html, где
// раньше загрузка файла (книги, обложки, импорт) была обычным нестилизованным
// <input type="file"> без этого поведения.
// ─────────────────────────────────────────────

function onDragOver(e, zoneId) {
  e.preventDefault();
  document.getElementById(zoneId).classList.add('drag-over');
}

function onDragLeave(zoneId) {
  document.getElementById(zoneId).classList.remove('drag-over');
}

function onDrop(e, inputId, zoneId) {
  e.preventDefault();
  onDragLeave(zoneId);
  const file = e.dataTransfer.files[0];
  if (!file) return;
  const input = document.getElementById(inputId);
  const dt    = new DataTransfer();
  dt.items.add(file);
  input.files = dt.files;
  input.dispatchEvent(new Event('change'));
}

function onFileSelected(inputId, zoneId, selId) {
  const file = document.getElementById(inputId).files[0];
  if (!file) return;
  const zone = document.getElementById(zoneId);
  const sel  = document.getElementById(selId);
  const name = document.getElementById(`${selId}-name`);
  zone.style.display = 'none';
  sel.classList.remove('hidden');
  if (name) name.textContent = file.name;
}

function clearFile(inputId, zoneId, selId) {
  document.getElementById(inputId).value = '';
  document.getElementById(zoneId).style.display = '';
  document.getElementById(selId).classList.add('hidden');
}

/* ═══════════════════════════════════════════
   УНИВЕРСАЛЬНЫЙ ПРОСМОТРЩИК ДОКУМЕНТОВ
   Открывает PDF / DOCX / изображения / текст прямо в браузере,
   без обязательного скачивания. Скачать можно по желанию —
   кнопка всегда есть в шапке окна.
   Используется на всех страницах (библиотека, домашние задания,
   материалы уроков и т.д.) — просто вызовите:
     openDocumentReader(url)
   или, если у файла в базе есть человекочитаемое имя:
     openDocumentReader(url, { title: 'Реальное имя.docx' })
═══════════════════════════════════════════ */

function _docReaderExt(nameOrUrl) {
  const clean = nameOrUrl.split('?')[0].split('#')[0];
  const parts = clean.split('.');
  return parts.length > 1 ? parts.pop().toLowerCase() : '';
}

function openDocumentReader(url, opts) {
  opts = opts || {};
  const title = opts.title || decodeURIComponent(url.split('/').pop().split('?')[0]);
  // Расширение всегда берём из настоящего пути файла (url), а не из
  // человекочитаемого названия (title) — у книги может быть название вроде
  // «1» или «Война и мир» без точки и расширения, и раньше именно это
  // ломало определение формата: читалка не понимала, что открывать, и
  // всегда показывала «Формат «.?» пока нельзя открыть».
  const ext = _docReaderExt(url);

  closeDocumentReader(); // на случай если уже открыт другой

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.id = 'docReaderOverlay';
  overlay.onclick = (e) => { if (e.target === overlay) closeDocumentReader(); };

  overlay.innerHTML = `
    <div class="modal modal-fs" style="max-width:960px;display:flex;flex-direction:column">
      <div class="modal-header">
        <span style="font-size:1.3rem">${_docReaderIcon(ext)}</span>
        <div class="modal-title" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_escapeHtml(title)}</div>
        <a href="${url}" download class="btn btn-ghost btn-sm" title="Скачать файл">📥 Скачать</a>
        <button class="btn btn-ghost btn-sm" onclick="closeDocumentReader()" title="Закрыть">✕</button>
      </div>
      <div class="modal-body" id="docReaderBody" style="flex:1;overflow:auto;padding:0">
        <div class="empty-state" style="padding:60px 20px">
          <div class="empty-state-icon">⏳</div>
          <p>Загружаю документ...</p>
        </div>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.addEventListener('keydown', _docReaderEscHandler);

  _docReaderRender(url, ext);
}

function closeDocumentReader() {
  const overlay = document.getElementById('docReaderOverlay');
  if (overlay) overlay.remove();
  document.removeEventListener('keydown', _docReaderEscHandler);
  // EPUB держит книгу открытой в памяти (JSZip и т.д.) — освобождаем при закрытии.
  if (_docReaderEpubBook) {
    try { _docReaderEpubBook.destroy(); } catch (e) { /* книга уже могла быть частично выгружена */ }
    _docReaderEpubBook = null;
    _docReaderEpubRendition = null;
  }
}

function _docReaderEscHandler(e) {
  if (e.key === 'Escape') { closeDocumentReader(); return; }
  // Стрелки листают открытую EPUB-книгу, если сейчас открыта именно она.
  if (_docReaderEpubRendition) {
    if (e.key === 'ArrowLeft') _docReaderEpubRendition.prev();
    else if (e.key === 'ArrowRight') _docReaderEpubRendition.next();
  }
}

function _docReaderIcon(ext) {
  if (ext === 'pdf') return '📕';
  if (['docx', 'doc'].includes(ext)) return '📘';
  if (['xlsx', 'xls', 'csv'].includes(ext)) return '📗';
  if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext)) return '🖼️';
  if (ext === 'epub') return '📚';
  if (ext === 'fb2') return '📖';
  if (ext === 'rtf') return '📝';
  return '📄';
}

function _escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

async function _docReaderRender(url, ext) {
  const body = document.getElementById('docReaderBody');
  if (!body) return; // окно уже закрыли, пока грузилось

  try {
    if (ext === 'pdf') {
      await _docReaderRenderPdf(url, body);
      return;
    }

    if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext)) {
      body.innerHTML = `<div style="padding:20px;text-align:center"><img src="${url}" style="max-width:100%;max-height:74vh;border-radius:var(--radius-lg)"></div>`;
      return;
    }

    if (ext === 'docx') {
      if (typeof mammoth === 'undefined') {
        body.innerHTML = _docReaderFallback(url, 'Просмотрщик документов ещё не загрузился, попробуйте ещё раз через секунду.');
        return;
      }
      const res = await fetch(url);
      if (!res.ok) throw new Error('network');
      const buf = await res.arrayBuffer();
      const result = await mammoth.convertToHtml({ arrayBuffer: buf });
      body.innerHTML = `<div class="doc-reader-box"><div class="doc-reader-content">${result.value}</div></div>`;
      return;
    }

    if (ext === 'txt') {
      const res = await fetch(url);
      if (!res.ok) throw new Error('network');
      const text = await res.text();
      body.innerHTML = `<div class="doc-reader-box"><pre class="doc-reader-pre">${_escapeHtml(text)}</pre></div>`;
      return;
    }

    if (['xlsx', 'xls', 'csv'].includes(ext)) {
      if (typeof XLSX === 'undefined') {
        body.innerHTML = _docReaderFallback(url, 'Просмотр таблиц пока недоступен — скачайте файл, чтобы открыть его в Excel.');
        return;
      }
      const res = await fetch(url);
      if (!res.ok) throw new Error('network');
      const buf = await res.arrayBuffer();
      const wb = XLSX.read(buf, { type: 'array' });
      const firstSheet = wb.Sheets[wb.SheetNames[0]];
      const html = XLSX.utils.sheet_to_html(firstSheet);
      body.innerHTML = `<div class="doc-reader-box" style="overflow:auto">${html}</div>`;
      return;
    }

    if (ext === 'epub') {
      await _docReaderRenderEpub(url, body);
      return;
    }

    if (ext === 'fb2') {
      const res = await fetch(url);
      if (!res.ok) throw new Error('network');
      const text = await res.text();
      const html = _fb2ToHtml(text);
      if (html === null) {
        body.innerHTML = _docReaderFallback(url, 'Не удалось разобрать файл FB2 для просмотра. Попробуйте скачать файл.');
        return;
      }
      body.innerHTML = `<div class="doc-reader-box"><div class="doc-reader-content">${html}</div></div>`;
      return;
    }

    if (ext === 'rtf') {
      const res = await fetch(url);
      if (!res.ok) throw new Error('network');
      // Сам файл RTF — это 7-битный ASCII-текст (не-ASCII символы уже
      // закодированы внутри как \'xx / \uNNNN), поэтому читать как текст
      // безопасно для любой кодировки исходного документа.
      const raw = await res.text();
      const plain = _rtfToPlainText(raw);
      if (plain === null) {
        body.innerHTML = _docReaderFallback(url, 'Не удалось разобрать файл RTF для просмотра. Попробуйте скачать файл.');
        return;
      }
      const html = plain
        .split(/\n{2,}/)
        .map(p => p.trim())
        .filter(Boolean)
        .map(p => `<p>${_escapeHtml(p).replace(/\n/g, '<br>')}</p>`)
        .join('');
      body.innerHTML = `<div class="doc-reader-box"><div class="doc-reader-content">${html || '<p><em>Пустой документ</em></p>'}</div></div>`;
      return;
    }

    // Форматы без предпросмотра в браузере (старый бинарный .doc и т.п.)
    body.innerHTML = _docReaderFallback(url, `Формат «.${ext || '?'}» пока нельзя открыть прямо в браузере — нажмите «Скачать», чтобы открыть файл на своём устройстве.`);
  } catch (err) {
    body.innerHTML = _docReaderFallback(url, 'Не удалось загрузить документ для просмотра. Попробуйте скачать файл.');
  }
}

function _docReaderFallback(url, message) {
  return `
    <div class="empty-state" style="padding:60px 20px">
      <div class="empty-state-icon">📄</div>
      <p>${_escapeHtml(message)}</p>
      <a href="${url}" download class="btn btn-primary btn-sm" style="margin-top:12px">📥 Скачать файл</a>
    </div>`;
}

/* ─── PDF: рендерим страницы через PDF.js в <canvas> ───
   Раньше PDF показывался через <iframe src="...pdf">, что отлично
   работает в десктопном Chrome/Firefox (у них есть встроенный PDF-плагин),
   но НЕ работает в мобильном Chrome/большинстве мобильных браузеров —
   там iframe с PDF просто открывает системный диалог "Открыть/Скачать"
   вместо показа содержимого. PDF.js рендерит страницы сам, одинаково
   на телефоне и на компьютере. */
async function _docReaderRenderPdf(url, body) {
  if (typeof pdfjsLib === 'undefined') {
    body.innerHTML = _docReaderFallback(url, 'Просмотрщик PDF ещё не загрузился, попробуйте открыть ещё раз через секунду.');
    return;
  }
  if (!pdfjsLib.GlobalWorkerOptions.workerSrc) {
    pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js';
  }

  body.innerHTML = `
    <div id="pdfPagesWrap" style="background:#525659;min-height:100%;padding:16px 12px;display:flex;flex-direction:column;align-items:center;gap:14px">
      <div class="empty-state" style="padding:40px 20px;color:#fff">
        <div class="empty-state-icon">⏳</div>
        <p>Загружаю страницы PDF...</p>
      </div>
    </div>`;
  const wrap = document.getElementById('pdfPagesWrap');

  try {
    const pdf = await pdfjsLib.getDocument(url).promise;
    if (!document.getElementById('pdfPagesWrap')) return; // модалку уже закрыли, пока грузился документ
    wrap.innerHTML = ''; // убираем "Загружаю..."

    const availableWidth = Math.max(280, wrap.clientWidth - 24);
    const dpr = window.devicePixelRatio || 1;

    for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
      // Если модалку закрыли посреди рендера — прекращаем, чтобы не грузить
      // страницы впустую и не дёргать несуществующий DOM.
      if (!document.getElementById('pdfPagesWrap')) return;

      const page = await pdf.getPage(pageNum);
      const baseViewport = page.getViewport({ scale: 1 });
      const cssScale = Math.min(availableWidth / baseViewport.width, 1.6);
      const renderViewport = page.getViewport({ scale: cssScale * dpr });

      const canvas = document.createElement('canvas');
      canvas.width  = Math.ceil(renderViewport.width);
      canvas.height = Math.ceil(renderViewport.height);
      canvas.style.width     = `${Math.ceil(baseViewport.width * cssScale)}px`;
      canvas.style.maxWidth  = '100%';
      canvas.style.background = '#fff';
      canvas.style.boxShadow  = '0 1px 6px rgba(0,0,0,0.35)';

      await page.render({ canvasContext: canvas.getContext('2d'), viewport: renderViewport }).promise;
      if (!document.getElementById('pdfPagesWrap')) return;
      wrap.appendChild(canvas);
    }
  } catch (err) {
    body.innerHTML = _docReaderFallback(url, 'Не удалось загрузить PDF для просмотра. Попробуйте скачать файл.');
  }
}


let _docReaderEpubBook      = null;
let _docReaderEpubRendition = null;

async function _docReaderRenderEpub(url, body) {
  if (typeof ePub === 'undefined') {
    body.innerHTML = _docReaderFallback(url, 'Просмотрщик книг ещё не загрузился, попробуйте открыть ещё раз через секунду.');
    return;
  }

  body.innerHTML = `
    <div id="epubReaderArea" style="height:78vh;display:flex;flex-direction:column">
      <div id="epubViewer" style="flex:1;position:relative;background:#fff"></div>
      <div style="display:flex;align-items:center;justify-content:center;gap:18px;padding:10px;border-top:1px solid var(--border)">
        <button class="btn btn-ghost btn-sm" onclick="_docReaderEpubRendition && _docReaderEpubRendition.prev()">← Назад</button>
        <span id="epubReaderProgress" style="font-size:0.85rem;color:var(--text-secondary,#888);min-width:48px;text-align:center">…</span>
        <button class="btn btn-ghost btn-sm" onclick="_docReaderEpubRendition && _docReaderEpubRendition.next()">Вперёд →</button>
      </div>
    </div>`;

  try {
    const book = ePub(url);
    _docReaderEpubBook = book;
    const rendition = book.renderTo('epubViewer', { width: '100%', height: '100%', flow: 'paginated' });
    _docReaderEpubRendition = rendition;
    await rendition.display();

    // Клик по левой/правой половине страницы тоже листает — привычно для читалок.
    rendition.on('rendered', () => {
      const iframeDoc = rendition.getContents()[0] && rendition.getContents()[0].document;
      if (!iframeDoc) return;
      iframeDoc.addEventListener('click', (e) => {
        const w = iframeDoc.defaultView.innerWidth;
        if (e.clientX < w / 3) rendition.prev();
        else if (e.clientX > (w * 2) / 3) rendition.next();
      });
    });

    book.ready
      .then(() => book.locations.generate(1200))
      .then(() => {
        rendition.on('relocated', (loc) => {
          const el = document.getElementById('epubReaderProgress');
          if (!el || !book.locations || !book.locations.length()) return;
          const pct = Math.round(book.locations.percentageFromCfi(loc.start.cfi) * 100);
          el.textContent = `${pct}%`;
        });
      })
      .catch(() => { /* прогресс не критичен — книга и так читается */ });
  } catch (err) {
    body.innerHTML = _docReaderFallback(url, 'Не удалось открыть книгу EPUB для просмотра. Попробуйте скачать файл.');
  }
}

/* ─── FB2: это обычный XML — парсим и превращаем в HTML сами ─── */
function _fb2GetHrefAttr(el) {
  for (const attr of el.attributes) {
    if (/href$/i.test(attr.name)) return attr.value;
  }
  return null;
}

function _fb2ToHtml(xmlText) {
  let xml;
  try {
    xml = new DOMParser().parseFromString(xmlText, 'application/xml');
  } catch (e) {
    return null;
  }
  if (xml.querySelector('parsererror')) return null;

  const binaries = {};
  xml.querySelectorAll('binary').forEach((b) => {
    const id = b.getAttribute('id');
    const contentType = b.getAttribute('content-type') || 'image/jpeg';
    const data = (b.textContent || '').replace(/\s+/g, '');
    if (id && data) binaries[id] = `data:${contentType};base64,${data}`;
  });

  const bookTitle = xml.querySelector('title-info > book-title')?.textContent?.trim() || '';
  let authorStr = '';
  xml.querySelectorAll('title-info > author').forEach((a) => {
    const first = a.querySelector('first-name')?.textContent?.trim() || '';
    const last  = a.querySelector('last-name')?.textContent?.trim() || '';
    const nm = `${first} ${last}`.trim();
    if (nm) authorStr += (authorStr ? ', ' : '') + nm;
  });

  function walk(node) {
    let html = '';
    node.childNodes.forEach((child) => {
      if (child.nodeType === 3) { html += _escapeHtml(child.textContent); return; }
      if (child.nodeType !== 1) return;
      const tag = child.tagName.toLowerCase();
      switch (tag) {
        case 'section':    html += `<div class="fb2-section">${walk(child)}</div>`; break;
        case 'title':      html += `<h2>${walk(child)}</h2>`; break;
        case 'subtitle':   html += `<h3>${walk(child)}</h3>`; break;
        case 'p':          html += `<p>${walk(child)}</p>`; break;
        case 'empty-line': html += `<br>`; break;
        case 'emphasis':   html += `<em>${walk(child)}</em>`; break;
        case 'strong':     html += `<strong>${walk(child)}</strong>`; break;
        case 'stanza':     html += `<div class="fb2-stanza">${walk(child)}</div>`; break;
        case 'poem':       html += `<div class="fb2-poem">${walk(child)}</div>`; break;
        case 'v':          html += `<div class="fb2-verse-line">${walk(child)}</div>`; break;
        case 'epigraph':   html += `<div class="fb2-epigraph">${walk(child)}</div>`; break;
        case 'cite':       html += `<blockquote>${walk(child)}</blockquote>`; break;
        case 'image': {
          const href = _fb2GetHrefAttr(child);
          const key = href ? href.replace('#', '') : null;
          if (key && binaries[key]) html += `<img src="${binaries[key]}">`;
          break;
        }
        default: html += walk(child);
      }
    });
    return html;
  }

  const bodies = Array.from(xml.querySelectorAll('body'));
  const mainBody = bodies.find((b) => b.getAttribute('name') !== 'notes') || bodies[0];
  if (!mainBody) return null;

  let coverHtml = '';
  const coverImg = xml.querySelector('coverpage image');
  if (coverImg) {
    const href = _fb2GetHrefAttr(coverImg);
    const key = href ? href.replace('#', '') : null;
    if (key && binaries[key]) {
      coverHtml = `<div style="text-align:center;margin-bottom:20px"><img src="${binaries[key]}" style="max-width:280px;border-radius:8px"></div>`;
    }
  }

  const headerHtml = bookTitle
    ? `<h1 style="text-align:center">${_escapeHtml(bookTitle)}</h1>${authorStr ? `<p style="text-align:center;color:var(--text-secondary,#888)">${_escapeHtml(authorStr)}</p>` : ''}`
    : '';

  return coverHtml + headerHtml + walk(mainBody);
}

/* ─── RTF: лёгкий парсер control words → обычный текст ───
   Не претендует на 100% формата (таблицы/сноски игнорируются), но
   корректно достаёт основной текст, включая кириллицу (cp1251 через
   \'xx и юникодные \uNNNN — оба варианта одинаково часто встречаются
   в старых файлах книг/документов). */
const _RTF_CP1251_HIGH = {
  0x80:'Ђ',0x81:'Ѓ',0x82:'‚',0x83:'ѓ',0x84:'„',0x85:'…',0x86:'†',0x87:'‡',
  0x88:'€',0x89:'‰',0x8A:'Љ',0x8B:'‹',0x8C:'Њ',0x8D:'Ќ',0x8E:'Ћ',0x8F:'Џ',
  0x90:'ђ',0x91:'‘',0x92:'’',0x93:'“',0x94:'”',0x95:'•',0x96:'–',0x97:'—',
  0x99:'™',0x9A:'љ',0x9B:'›',0x9C:'њ',0x9D:'ќ',0x9E:'ћ',0x9F:'џ',
  0xA0:'\u00A0',0xA1:'Ў',0xA2:'ў',0xA3:'Ј',0xA4:'¤',0xA5:'Ґ',0xA6:'¦',0xA7:'§',
  0xA8:'Ё',0xA9:'©',0xAA:'Є',0xAB:'«',0xAC:'¬',0xAD:'\u00AD',0xAE:'®',0xAF:'Ї',
  0xB0:'°',0xB1:'±',0xB2:'І',0xB3:'і',0xB4:'ґ',0xB5:'µ',0xB6:'¶',0xB7:'·',
  0xB8:'ё',0xB9:'№',0xBA:'є',0xBB:'»',0xBC:'ј',0xBD:'Ѕ',0xBE:'ѕ',0xBF:'ї'
};
function _rtfDecodeByte(byte) {
  if (byte >= 0xC0) return String.fromCharCode(0x0410 + (byte - 0xC0)); // А-я
  if (_RTF_CP1251_HIGH[byte]) return _RTF_CP1251_HIGH[byte];
  return String.fromCharCode(byte);
}

const _RTF_IGNORE_DESTINATIONS = new Set([
  'fonttbl', 'colortbl', 'stylesheet', 'info', 'generator', 'pict', 'object',
  'footnote', 'header', 'footer', 'headerf', 'footerf', 'headerl', 'headerr',
  'footerl', 'footerr', 'listtable', 'listoverridetable', 'rsidtbl', 'xmlnstbl',
  'latentstyles', 'themedata', 'colorschememapping', 'datastore', 'revtbl',
  'shppict', 'nonshppict', 'bkmkstart', 'bkmkend', 'fldinst', 'panose', 'falt',
  'filetbl', 'operator', 'pntxta', 'pntxtb'
]);

function _rtfToPlainText(rtf) {
  if (!rtf || rtf.charCodeAt(0) !== 0x7B) return null; // должно начинаться с "{"
  let out = '';
  let depth = 0;
  let skipDepth = null;
  const n = rtf.length;
  let i = 0;
  while (i < n) {
    const ch = rtf[i];

    if (ch === '{') { depth++; i++; continue; }
    if (ch === '}') {
      if (skipDepth !== null && depth === skipDepth) skipDepth = null;
      depth--; i++; continue;
    }
    if (skipDepth !== null) {
      // Внутри пропускаемого destination экранированные \{ \} \\ всё равно
      // нужно перепрыгивать парой байт, иначе следующий символ (сам "{"/"}")
      // будет ошибочно воспринят как настоящая граница группы на строках
      // выше и собьёт учёт глубины вложенности.
      if (ch === '\\' && i + 1 < n && (rtf[i + 1] === '\\' || rtf[i + 1] === '{' || rtf[i + 1] === '}')) { i += 2; continue; }
      i++; continue;
    }

    if (ch === '\\') {
      i++;
      if (i >= n) break;
      const c2 = rtf[i];

      if (c2 === '\\' || c2 === '{' || c2 === '}') { out += c2; i++; continue; }

      if (c2 === "'") { // \'hh — байт в текущей кодовой странице (обычно cp1251)
        const hex = rtf.substr(i + 1, 2);
        i += 3;
        const byte = parseInt(hex, 16);
        if (!isNaN(byte)) out += _rtfDecodeByte(byte);
        continue;
      }

      if (c2 === '*') { i++; continue; } // маркер "необязательный destination", сама группа обработается ниже

      if (c2 === '~') { out += '\u00A0'; i++; continue; } // неразрывный пробел
      if (c2 === '-' || c2 === '_') { i++; continue; }    // мягкий перенос / неразрывный дефис — пропускаем

      let word = '';
      while (i < n && /[a-zA-Z]/.test(rtf[i])) { word += rtf[i]; i++; }

      if (!word) { i++; continue; } // одиночный экранированный непечатный символ — пропускаем

      let numStr = '';
      let neg = false;
      if (rtf[i] === '-') { neg = true; i++; }
      while (i < n && /[0-9]/.test(rtf[i])) { numStr += rtf[i]; i++; }
      if (rtf[i] === ' ') i++; // один пробел-разделитель после control word поглощается

      const num = numStr ? (neg ? -parseInt(numStr, 10) : parseInt(numStr, 10)) : null;

      if (_RTF_IGNORE_DESTINATIONS.has(word)) { skipDepth = depth; continue; }
      if (word === 'par' || word === 'line' || word === 'row') { out += '\n\n'; continue; }
      if (word === 'tab') { out += '\t'; continue; }
      if (word === 'u') {
        if (num !== null) out += String.fromCharCode(num < 0 ? num + 65536 : num);
        // за \uN обычно следует один символ-заменитель для программ без юникода — пропускаем его
        if (i < n && rtf[i] !== '\\' && rtf[i] !== '{' && rtf[i] !== '}') i++;
        continue;
      }
      // остальные control words (шрифты/форматирование) не влияют на текст — просто пропускаем
      continue;
    }

    out += ch;
    i++;
  }

  return out.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}
