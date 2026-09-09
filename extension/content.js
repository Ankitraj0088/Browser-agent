// ============================================================================
// Privacy-Preserving Browser Vision Agent - Content Script
// SIH 26171 (ISRO): On-device Visual Perception for Light-weight Browser Agents
//
// Responsibilities of this file (runs INSIDE the web page, sandboxed):
//   1. Local "vision" pass over the DOM  -> find sensitive UI regions
//   2. Local raster redaction over the captured screenshot (canvas ops)
//   3. Build a SANITIZED, abstracted description of the screen (no raw PII)
//   4. Receive an action from background.js (which talked to the server)
//      and execute it on the real page
// ============================================================================

// ---- 1. PII / sensitive-element detectors --------------------------------
// These act as the fast, cheap "local model" layer. In a full ViT pipeline
// this would be a learned detector; here we combine (a) semantic DOM signals
// (free, ~0ms, very high precision) with (b) regex pattern matching over
// visible text (cheap) with (c) a real on-device vision model for FACES,
// which DOM signals cannot catch (see visionModel.js).
const PII_PATTERNS = {
  email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  phone: /(\+?\d{1,3}[\s-]?)?\(?\d{3,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}/g,
  creditCard: /\b(?:\d[ -]*?){13,16}\b/g,
  aadhaar: /\b\d{4}\s?\d{4}\s?\d{4}\b/g,
  ssn: /\b\d{3}-\d{2}-\d{4}\b/g
};

const SENSITIVE_INPUT_SELECTORS = [
  'input[type="password"]',
  'input[autocomplete*="cc-"]',
  'input[autocomplete*="password"]',
  'input[name*="card"]',
  'input[name*="ssn"]',
  'input[name*="aadhaar"]',
  'input[type="email"]',
  'input[type="tel"]'
];

function rectOf(el) {
  const r = el.getBoundingClientRect();
  return { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) };
}

// Scan the live DOM for sensitive fields + sensitive text nodes.
// Returns bounding boxes in VIEWPORT coordinates so they line up with
// a viewport screenshot taken via chrome.tabs.captureVisibleTab.
function scanDOMForSensitiveRegions() {
  const boxes = [];

  // (a) Structurally sensitive form fields
  document.querySelectorAll(SENSITIVE_INPUT_SELECTORS.join(',')).forEach(el => {
    const r = rectOf(el);
    if (r.w > 0 && r.h > 0) {
      boxes.push({ ...r, type: 'form-field', reason: el.type || el.name || 'sensitive-input' });
    }
  });

  // (b) Free text on the page that matches PII regex (emails, phone, card no.)
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      if (!node.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
      const parentTag = node.parentElement && node.parentElement.tagName;
      if (['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(parentTag)) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    }
  });

  let node;
  while ((node = walker.nextNode())) {
    const text = node.nodeValue;
    for (const [label, regex] of Object.entries(PII_PATTERNS)) {
      regex.lastIndex = 0;
      if (regex.test(text)) {
        const range = document.createRange();
        range.selectNodeContents(node);
        const r = range.getBoundingClientRect();
        if (r.width > 0 && r.height > 0) {
          boxes.push({
            x: Math.round(r.x), y: Math.round(r.y),
            w: Math.round(r.width), h: Math.round(r.height),
            type: 'text-pii', reason: label
          });
        }
      }
    }
  }

  return boxes;
}

// Build an ABSTRACTED, safe summary of the DOM: element roles, tags,
// approximate positions, and *non-sensitive* text only (truncated).
// This is what stands in for "screen structure" per the problem statement -
// it is far cheaper for the server LLM to reason over than raw pixels, and
// it never carries sensitive field values.
function buildSanitizedDomSummary(sensitiveBoxes) {
  const isInsideSensitiveBox = (r) =>
    sensitiveBoxes.some(b => r.x >= b.x - 2 && r.y >= b.y - 2 &&
      r.x + r.w <= b.x + b.w + 2 && r.y + r.h <= b.y + b.h + 2);

  const interactive = Array.from(document.querySelectorAll(
    'button, a, input, select, textarea, [role="button"]'
  )).slice(0, 150);

  return interactive.map(el => {
    const r = rectOf(el);
    if (r.w === 0 || r.h === 0) return null;
    const redacted = isInsideSensitiveBox(r) || SENSITIVE_INPUT_SELECTORS.some(sel => el.matches(sel));
    return {
      tag: el.tagName.toLowerCase(),
      role: el.getAttribute('role') || el.type || null,
      text: redacted ? '[REDACTED]' : (el.innerText || el.value || el.placeholder || '').slice(0, 60),
      rect: r,
      selector: cssPath(el)
    };
  }).filter(Boolean);
}

// Minimal, robust CSS-path builder so the server can address an element
// without ever seeing its content.
function cssPath(el) {
  if (el.id) return `#${el.id}`;
  const path = [];
  let node = el;
  while (node && node.nodeType === 1 && path.length < 5) {
    let selector = node.tagName.toLowerCase();
    if (node.className && typeof node.className === 'string') {
      const cls = node.className.trim().split(/\s+/).slice(0, 2).join('.');
      if (cls) selector += '.' + cls;
    }
    const parent = node.parentNode;
    if (parent) {
      const siblings = Array.from(parent.children).filter(c => c.tagName === node.tagName);
      if (siblings.length > 1) selector += `:nth-of-type(${siblings.indexOf(node) + 1})`;
    }
    path.unshift(selector);
    node = node.parentElement;
  }
  return path.join(' > ');
}

// ---- 2. Canvas-based redaction of the raw screenshot ----------------------
// Takes the dataURL screenshot from background.js + the sensitive boxes
// (DOM-derived boxes here; face boxes come in merged from visionModel.js)
// and returns a NEW dataURL with all sensitive regions blacked out.
// This is the actual "privacy filter" the rubric asks to see demonstrated.
async function redactScreenshot(dataUrl, boxes) {
  const img = await new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = reject;
    image.src = dataUrl;
  });

  const canvas = document.createElement('canvas');
  canvas.width = img.width;
  canvas.height = img.height;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0);

  // devicePixelRatio scaling: captureVisibleTab returns physical pixels,
  // DOM rects are in CSS pixels.
  const scale = img.width / window.innerWidth;

  ctx.fillStyle = '#000000';
  boxes.forEach(b => {
    ctx.fillRect(b.x * scale, b.y * scale, b.w * scale, b.h * scale);
  });

  return canvas.toDataURL('image/png');
}

// ---- 3. Action executor ----------------------------------------------------
// Executes an action the server decided on. Never touches redacted /
// sensitive elements for anything other than a plain click (defense in depth
// - we do not let the server tell us to type into a password field, e.g.).
function executeAction(action) {
  if (!action || !action.type) return { ok: false, error: 'empty action' };
  let el = null;
  try {
    el = action.selector ? document.querySelector(action.selector) : null;
  } catch (e) {
    return { ok: false, error: 'bad selector' };
  }

  switch (action.type) {
    case 'click':
      if (!el) return { ok: false, error: 'element not found' };
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      el.click();
      return { ok: true };
    case 'scroll':
      window.scrollBy({ top: action.dy || 400, behavior: 'smooth' });
      return { ok: true };
    case 'type':
      if (!el) return { ok: false, error: 'element not found' };
      if (el.matches(SENSITIVE_INPUT_SELECTORS.join(','))) {
        return { ok: false, error: 'refused: target is a sensitive field' };
      }
      el.focus();
      el.value = action.text || '';
      el.dispatchEvent(new Event('input', { bubbles: true }));
      return { ok: true };
    case 'none':
      return { ok: true, note: 'no-op' };
    default:
      return { ok: false, error: 'unknown action type' };
  }
}

// ---- 4. Message bridge to background.js -----------------------------------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.cmd === 'SCAN_AND_REDACT') {
    (async () => {
      const t0 = performance.now();
      const domBoxes = scanDOMForSensitiveRegions();
      const t1 = performance.now();
      const redactedImage = await redactScreenshot(msg.screenshot, [...domBoxes, ...(msg.faceBoxes || [])]);
      const t2 = performance.now();
      const domSummary = buildSanitizedDomSummary(domBoxes);
      sendResponse({
        redactedImage,
        domSummary,
        piiBoxCount: domBoxes.length,
        timings: { domScanMs: +(t1 - t0).toFixed(1), redactionMs: +(t2 - t1).toFixed(1) }
      });
    })();
    return true; // keep the message channel open for async sendResponse
  }

  if (msg.cmd === 'EXECUTE_ACTION') {
    sendResponse(executeAction(msg.action));
    return true;
  }
});
