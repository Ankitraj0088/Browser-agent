// ============================================================================
// Background service worker
// - Captures the visible tab (only place with permission to do this)
// - Orchestrates: capture -> content script (DOM scan + redaction)
//                -> POST sanitized payload to local server
//                -> relay returned action back to content script to execute
// ============================================================================

const SERVER_URL = 'http://localhost:5050/agent/act';

async function captureActiveTab() {
  return new Promise((resolve, reject) => {
    chrome.tabs.captureVisibleTab(null, { format: 'png' }, (dataUrl) => {
      if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
      else resolve(dataUrl);
    });
  });
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

// Full pipeline, callable from the popup.
async function runAgentCycle(task, faceBoxes, preCapturedScreenshot) {
  const tab = await getActiveTab();
  const tNet0 = performance.now();

  const screenshot = preCapturedScreenshot || await captureActiveTab();

  // Ask the content script (runs in page context) to do local DOM scanning
  // and canvas redaction. Face boxes (if computed in the popup) are merged in.
  const scanResult = await chrome.tabs.sendMessage(tab.id, {
    cmd: 'SCAN_AND_REDACT',
    screenshot,
    faceBoxes: faceBoxes || []
  });

  // Only the REDACTED image + ABSTRACTED dom summary ever leave the device.
  const serverResp = await fetch(SERVER_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      image: scanResult.redactedImage,
      dom_summary: scanResult.domSummary,
      task
    })
  });
  const rawText = await serverResp.text();
  if (!rawText) {
    throw new Error(
      `Server returned an empty response (HTTP ${serverResp.status}). ` +
      `Most likely Chrome blocked the request to localhost (Private Network Access) ` +
      `- make sure server.py has been restarted after the latest changes, ` +
      `or check the server terminal for a crash.`
    );
  }
  let serverJson;
  try {
    serverJson = JSON.parse(rawText);
  } catch (e) {
    throw new Error(`Server response was not valid JSON (HTTP ${serverResp.status}): ${rawText.slice(0, 200)}`);
  }
  const tNet1 = performance.now();

  let execResult = { ok: true, note: 'no action requested' };
  if (serverJson.action && serverJson.action.type !== 'none') {
    execResult = await chrome.tabs.sendMessage(tab.id, {
      cmd: 'EXECUTE_ACTION',
      action: serverJson.action
    });
  }

  return {
    redactedImage: scanResult.redactedImage,
    piiBoxCount: scanResult.piiBoxCount,
    domScanMs: scanResult.timings.domScanMs,
    redactionMs: scanResult.timings.redactionMs,
    serverRoundTripMs: +(tNet1 - tNet0).toFixed(1),
    action: serverJson.action,
    reasoning: serverJson.reasoning,
    execResult
  };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.cmd === 'CAPTURE_ONLY') {
    captureActiveTab()
      .then(dataUrl => sendResponse({ dataUrl }))
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }
  if (msg.cmd === 'RUN_AGENT_CYCLE') {
    runAgentCycle(msg.task, msg.faceBoxes, msg.screenshot)
      .then(sendResponse)
      .catch(err => sendResponse({ error: String(err) }));
    return true; // async
  }
  if (msg.cmd === 'SIMULATE_ATTACK') {
    // Pretend a compromised/malicious server told the agent to type into
    // the password field. This proves the client-side gatekeeping actually
    // works, live, in front of judges - not just claimed in a slide.
    (async () => {
      const tab = await getActiveTab();
      const result = await chrome.tabs.sendMessage(tab.id, {
        cmd: 'EXECUTE_ACTION',
        action: { type: 'type', selector: 'input[type="password"]', text: 'HACKED_BY_MALICIOUS_SERVER' }
      });
      sendResponse(result);
    })();
    return true;
  }
});
