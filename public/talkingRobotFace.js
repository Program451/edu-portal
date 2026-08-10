/**
 * talkingRobotFace.js
 * ---------------------------------------------------------
 * Анимация РТА для cute_robot.glb.
 *
 * ИСТОРИЯ ПРОБЛЕМЫ (важно, если будете переделывать):
 * Изначально этот модуль пытался нарисовать лицо (глаза+рот) на
 * встроенном в модель меше с материалом "Layar", думая, что это
 * "экран" робота. Разбор самого .glb показал, что:
 *   - "глаза", которые видно на роботе — это НЕ текстура, а отдельная
 *     3D-геометрия (тёмный шар из материала Darker_Metal + маленький
 *     светлый блик из материала Material.001), встроенная в саму модель;
 *   - меш "Layar" — это просто чёрный кружок-подложка позади этих глаз,
 *     и его UV-развёртка устроена очень нетривиально (почти вся видимая
 *     поверхность берёт текстуру из крошечного пятна канваса), из-за чего
 *     нарисованный на нём рот либо не попадал в кадр вообще, либо было
 *     непонятно, применяется ли текстура на практике.
 *
 * РЕШЕНИЕ: вместо того, чтобы красить существующий меш (хрупко и плохо
 * проверяемо), создаём СВОЮ отдельную плоскость с рртом и ставим её
 * прямо перед лицевой панелью робота (несколько выступающей по Z, чтобы
 * гарантированно не быть перекрытой). Она никак не зависит от того, как
 * устроена UV-развёртка исходной модели — только от её bounding box,
 * который считается через three.js в рантайме (Box3), а не вручную.
 *
 * Требует: three.js (r128+), GLTFLoader.
 *
 * ИСПОЛЬЗОВАНИЕ (vanilla):
 * ---------------------------------------------------------
 *   const face = createTalkingFace(gltf.scene, THREE);
 *   face.connectAudioElement(audioEl);      // вариант A: есть <audio>
 *   face.attachSpeechSynthesis(utterance);  // вариант B: speechSynthesis
 *   face.setSpeaking(true / false);         // вариант C: вручную
 *   face.setStyle({ intensity, speed });    // подстройка под "стиль" ответа
 *   face.pulseWord('слово');                // пословная синхронизация
 *   face.pulseGap();                        // короткая пауза между словами
 *
 *   function animate() {
 *     requestAnimationFrame(animate);
 *     face.update();  // обязательно каждый кадр
 *     renderer.render(scene, camera);
 *   }
 * ---------------------------------------------------------
 */

function createTalkingFace(rootObject3D, THREE, options = {}) {
  const {
    canvasW = 512,
    canvasH = 256,
    mouthColor = '#7CFFCB',   // ярко-мятный — хорошо виден на тёмной/красной панели
    faceMaterialName = 'Layar', // используем только чтобы найти панель для позиционирования
  } = options;

  // --- 1. Определяем, где расположить рот -----------------------------------
  // Считаем bounding box всей модели через three.js (Box3) — это надёжнее,
  // чем вручную вычислять координаты по сырым данным .glb, т.к. учитывает
  // ВСЕ трансформации узлов автоматически.
  const overallBox = new THREE.Box3().setFromObject(rootObject3D);

  // Пытаемся найти лицевую панель ("Layar") — если найдём, используем именно
  // её bounding box для более точного позиционирования рта. Если нет —
  // используем общий bounding box модели как запасной вариант.
  let panelMesh = null;
  rootObject3D.traverse((obj) => {
    if (obj.isMesh && obj.material) {
      const mats = Array.isArray(obj.material) ? obj.material : [obj.material];
      if (mats.some((m) => m.name === faceMaterialName)) panelMesh = obj;
    }
  });

  let anchorParent = rootObject3D;
  let localCenterX = 0, localMouthY = 0, localMouthZ = 0, localWidth = 1;

  if (panelMesh) {
    panelMesh.geometry.computeBoundingBox();
    const bb = panelMesh.geometry.boundingBox;
    localCenterX = (bb.min.x + bb.max.x) / 2;
    // рот — в нижней части панели (глаза уже занимают верхне-среднюю часть)
    localMouthY = bb.min.y + (bb.max.y - bb.min.y) * 0.20;
    localMouthZ = bb.max.z + 0.04; // чуть выступает вперёд, чтобы не быть перекрытым
    localWidth = (bb.max.x - bb.min.x) * 0.7;
    anchorParent = panelMesh.parent || rootObject3D;
  } else {
    // Запасной вариант: общий bbox модели, верхняя треть по Y (типичная
    // область "головы"), самая передняя точка по Z.
    console.warn(
      `[talkingRobotFace] Меш с материалом "${faceMaterialName}" не найден — ` +
      `ставим рот по общему bounding box модели (может быть неточно).`
    );
    const size = new THREE.Vector3();
    overallBox.getSize(size);
    const center = new THREE.Vector3();
    overallBox.getCenter(center);
    localCenterX = center.x;
    localMouthY = overallBox.min.y + size.y * 0.65;
    localMouthZ = overallBox.max.z + 0.05;
    localWidth = size.x * 0.35;
    anchorParent = rootObject3D;
  }

  // --- 2. Canvas-текстура для рта (прозрачный фон) ---------------------------
  const canvas = document.createElement('canvas');
  canvas.width = canvasW;
  canvas.height = canvasH;
  const ctx = canvas.getContext('2d');
  const texture = new THREE.CanvasTexture(canvas);

  // MeshBasicMaterial — не зависит от освещения сцены, поэтому рот всегда
  // виден с одинаковой яркостью, независимо от света в AR-сцене.
  const planeGeo = new THREE.PlaneGeometry(localWidth, localWidth * (canvasH / canvasW) * 1.4);
  const planeMat = new THREE.MeshBasicMaterial({
    map: texture,
    transparent: true,
    depthWrite: false,
    side: THREE.DoubleSide,
  });
  const mouthMesh = new THREE.Mesh(planeGeo, planeMat);
  mouthMesh.position.set(localCenterX, localMouthY, localMouthZ);
  mouthMesh.renderOrder = 999; // рисуем поверх остальной геометрии
  mouthMesh.name = 'talkingFaceMouth';
  anchorParent.add(mouthMesh);

  // --- 3. Состояние анимации рта ----------------------------------------------
  const state = {
    speaking: false,
    mouthOpen: 0,          // 0..1 текущее раскрытие (сглаженное)
    targetOpen: 0,         // 0..1 целевое значение
    analyser: null,
    audioData: null,
    audioCtx: null,
    usingWordSync: false,  // true, пока приходят pulseWord() — отключает "жевание" синусоидой
    _usingBoundary: false,
    style: { intensity: 1, speed: 1 }, // подстройка под "стиль" ответа (см. setStyle)
  };

  function drawMouth() {
    ctx.clearRect(0, 0, canvasW, canvasH);

    const openness = Math.max(0.10, state.mouthOpen); // всегда виден хотя бы тонкой полоской
    const w = canvasW * 0.5;
    const h = canvasH * (0.14 + 0.62 * openness);
    const cx = canvasW / 2;
    const cy = canvasH / 2;

    ctx.fillStyle = mouthColor;
    ctx.beginPath();
    ctx.ellipse(cx, cy, w / 2, h / 2, 0, 0, Math.PI * 2);
    ctx.fill();

    texture.needsUpdate = true;
  }

  // --- 4. Источники сигнала "говорит" ----------------------------------------

  // A) Реальный анализ громкости из <audio> элемента
  function connectAudioElement(audioEl) {
    if (!audioEl) return;
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    state.audioCtx = state.audioCtx || new AudioCtx();
    const source = state.audioCtx.createMediaElementSource(audioEl);
    const analyser = state.audioCtx.createAnalyser();
    analyser.fftSize = 256;
    source.connect(analyser);
    analyser.connect(state.audioCtx.destination);
    state.analyser = analyser;
    state.audioData = new Uint8Array(analyser.frequencyBinCount);

    audioEl.addEventListener('play', () => setSpeaking(true));
    audioEl.addEventListener('pause', () => setSpeaking(false));
    audioEl.addEventListener('ended', () => setSpeaking(false));
  }

  // B) window.speechSynthesis — своих аудио-данных не даёт,
  //    поэтому имитируем "болтовню" на границах слов/символов
  function attachSpeechSynthesis(utterance) {
    utterance.onstart = () => setSpeaking(true);
    utterance.onend = () => setSpeaking(false);
    utterance.onerror = () => setSpeaking(false);
    utterance.onboundary = () => {
      state._usingBoundary = true;
      state.targetOpen = 0.4 + Math.random() * 0.6;
    };
  }

  // C) Ручное управление
  function setSpeaking(isSpeaking) {
    state.speaking = isSpeaking;
    if (!isSpeaking) {
      state.targetOpen = 0;
      state.usingWordSync = false;
      state._usingBoundary = false;
    }
  }

  // D) Подстройка "стиля" — считается один раз на весь ответ ИИ (см. analyzeSpeechStyle
  //    в ar-assistant.html): intensity — насколько широко открывается рот,
  //    speed — насколько быстро "жуёт" в паузах без точных данных по словам.
  function setStyle({ intensity = 1, speed = 1 } = {}) {
    state.style.intensity = Math.max(0.6, Math.min(1.6, intensity));
    state.style.speed = Math.max(0.6, Math.min(1.8, speed));
  }

  // E) Пословная синхронизация — вызывается на каждое слово озвучиваемого текста.
  //    Раскрытие рта зависит от длины слова и пунктуации, поэтому анимация
  //    "повторяет" ритм конкретной фразы, а не абстрактную синусоиду.
  function pulseWord(word = '') {
    state.usingWordSync = true;
    state.speaking = true;
    const clean = String(word).trim();
    if (!clean) { state.targetOpen = 0.1; return; }

    const len = clean.replace(/[^\wа-яёА-ЯЁәіңғүұқөһӘІҢҒҮҰҚӨҺ]/gu, '').length || 1;
    let base = Math.min(1, 0.32 + len * 0.07); // длиннее слово — шире открывание

    if (/[!?]/.test(clean)) base = Math.min(1, base + 0.28);      // эмоция/вопрос — шире
    if (/[.,;:]$/.test(clean)) base *= 0.7;                        // конец фразы — прикрываем

    state.targetOpen = Math.min(1, base * state.style.intensity);
  }

  // Короткая пауза между словами/предложениями — рот почти закрыт
  function pulseGap(amount = 0.1) {
    state.usingWordSync = true;
    state.targetOpen = amount;
  }

  // --- 5. Главный update(), звать каждый кадр ---------------------------------
  let last = performance.now();
  function update() {
    const now = performance.now();
    const dt = Math.min(0.1, (now - last) / 1000);
    last = now;

    if (state.analyser) {
      state.analyser.getByteFrequencyData(state.audioData);
      let sum = 0;
      for (let i = 0; i < state.audioData.length; i++) sum += state.audioData[i];
      const avg = sum / state.audioData.length / 255; // 0..1
      state.targetOpen = state.speaking ? Math.min(1, avg * 2.2) : 0;
    } else if (state.speaking && !state.usingWordSync && !state._usingBoundary) {
      // нет ни audio-анализа, ни пословной/boundary-синхронизации —
      // "жуём" синусоидой, скорость/амплитуда подстроены под style
      const speed = state.style.speed;
      const amp = 0.35 * state.style.intensity;
      state.targetOpen = (0.35 * state.style.intensity) + amp * Math.abs(Math.sin(now / (90 / speed)));
    }

    // сглаживание (чтобы рот не дёргался резко)
    state.mouthOpen += (state.targetOpen - state.mouthOpen) * Math.min(1, dt * 14);

    drawMouth();
  }

  drawMouth(); // первый кадр сразу, чтобы не было пустого экрана

  return {
    setSpeaking,
    connectAudioElement,
    attachSpeechSynthesis,
    setStyle,
    pulseWord,
    pulseGap,
    update,
    mesh: mouthMesh,
    texture,
  };
}

window.createTalkingFace = createTalkingFace;
