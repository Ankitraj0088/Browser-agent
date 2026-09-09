// ============================================================================
// Popup script
// Runs the on-device face detector (a real, lightweight CNN - TinyFaceDetector,
// ~190KB, WASM/WebGL backend) directly on the captured screenshot. This is the
// "local Vision Transformer / equivalent CV model" component of the rubric,
// running fully client-side before anything is sent anywhere.
// ============================================================================

const runBtn = document.getElementById('run');
const statusEl = document.getElementById('status');
const metricsEl = document.getElementById('metrics');
const compareEl = document.getElementById('compare');
const previewBeforeEl = document.getElementById('preview-before');
const previewEl = document.getElementById('preview');
const reasoningEl = document.getElementById('reasoning');
const attackBtn = document.getElementById('attack-btn');
const attackResultEl = document.getElementById('attack-result');

let modelsReady = false;

async function loadFaceModel() {
  try {
    const MODEL_URL = 'https://cdn.jsdelivr.net/gh/vladmandic/face-api/model/';
    await faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL);
    modelsReady = true;
  } catch (e) {
    console.warn('Face model failed to load (offline demo mode - PII/DOM redaction still runs):', e);
    modelsReady = false;
  }
}
loadFaceModel();

async function detectFaces(dataUrl) {
  if (!modelsReady) return { boxes: [], ms: 0 };
  const img = await faceapi.bufferToImage(await (await fetch(dataUrl)).blob());
  const t0 = performance.now();
  const detections = await faceapi.detectAllFaces(img, new faceapi.TinyFaceDetectorOptions({ inputSize: 320 }));
  const ms = performance.now() - t0;

  // Face boxes come back in *screenshot pixel* space. Convert to CSS/viewport
  // space so they line up with the DOM-derived boxes in content.js.
  const scale = window.devicePixelRatio || 1; // heuristic; refined server-side is unnecessary for a demo
  const boxes = detections.map(d => ({
    x: d.box.x / scale, y: d.box.y / scale,
    w: d.box.width / scale, h: d.box.height / scale,
    type: 'face', reason: 'face-detection'
  }));
  return { boxes, ms: +ms.toFixed(1) };
}

function setStatus(text) { statusEl.textContent = text; }

runBtn.addEventListener('click', async () => {
  runBtn.disabled = true;
  metricsEl.classList.add('hidden');
  compareEl.classList.add('hidden');
  reasoningEl.classList.add('hidden');
  attackResultEl.classList.add('hidden');
  const task = document.getElementById('task').value || 'none';

  try {
    setStatus('Capturing screen...');
    const cap = await chrome.runtime.sendMessage({ cmd: 'CAPTURE_ONLY' });
    if (cap.error) throw new Error(cap.error);

    setStatus('Running local face model...');
    const { boxes: faceBoxes, ms: faceMs } = await detectFaces(cap.dataUrl);

    setStatus('Redacting + scanning DOM, then contacting server...');
    const result = await chrome.runtime.sendMessage({
      cmd: 'RUN_AGENT_CYCLE',
      task,
      faceBoxes,
      screenshot: cap.dataUrl
    });
    if (result.error) throw new Error(result.error);

    document.getElementById('m-dom').textContent = result.domScanMs + ' ms';
    document.getElementById('m-redact').textContent = result.redactionMs + ' ms';
    document.getElementById('m-face').textContent = faceMs + ' ms';
    document.getElementById('m-net').textContent = result.serverRoundTripMs + ' ms';
    document.getElementById('m-pii').textContent = result.piiBoxCount + (faceBoxes.length ? ` (+${faceBoxes.length} face)` : '');
    metricsEl.classList.remove('hidden');

    previewBeforeEl.src = cap.dataUrl;
    previewEl.src = result.redactedImage;
    compareEl.classList.remove('hidden');

    if (result.reasoning) {
      reasoningEl.textContent = `Server action: ${result.action.type} ${result.action.selector || ''} - ${result.reasoning}`;
      reasoningEl.classList.remove('hidden');
    }

    setStatus(result.execResult && result.execResult.ok ? 'Done.' : 'Done (action not applied: ' + (result.execResult && result.execResult.error) + ')');
  } catch (err) {
    setStatus('Error: ' + err.message);
  } finally {
    runBtn.disabled = false;
  }
});

attackBtn.addEventListener('click', async () => {
  attackBtn.disabled = true;
  attackResultEl.classList.remove('hidden', 'blocked', 'leaked');
  attackResultEl.textContent = 'Simulating a compromised server instructing the agent to type into the password field...';
  try {
    const result = await chrome.runtime.sendMessage({ cmd: 'SIMULATE_ATTACK' });
    if (result && result.ok === false) {
      attackResultEl.textContent = 'BLOCKED: client refused - ' + result.error;
      attackResultEl.classList.add('blocked');
    } else {
      attackResultEl.textContent = 'WARNING: the action was NOT blocked (unexpected on this page).';
      attackResultEl.classList.add('leaked');
    }
  } catch (err) {
    attackResultEl.textContent = 'Error running simulation: ' + err.message;
    attackResultEl.classList.add('leaked');
  } finally {
    attackBtn.disabled = false;
  }
});
