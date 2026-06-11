// =============================================================================
// Verilay — AI App Verification Layer
// © 2026 Moses Ekbote. All rights reserved.
// Free for personal/open source use.
// Commercial use requires licence: moses@verilay.dev
// =============================================================================


console.log("[Verilay] app.js loading...");
var currentMethod = 'github';
var currentReport = null;
var currentFilesSample = '';
var currentLayers = {};
var activeLayer = null;
var activeMode = 'expert';

var savedReportId = null;

async function autoSaveReport(data) {
  // Silently save in background and show share URL when ready
  try {
    var reportData = Object.assign({}, data);
    var resp = await fetch('/save-report', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(reportData)
    });
    var result = await resp.json();
    if (result.report_id) {
      savedReportId = result.report_id;
      var shareUrl = window.location.origin + '/report/' + result.report_id;
      // Update status label
      var statusEl = document.getElementById('report-status');
      if (statusEl) statusEl.textContent = 'Report saved';
      // Show share banner
      var shareInput = document.getElementById('share-url');
      var shareBanner = document.getElementById('share-banner');
      if (shareInput) shareInput.value = shareUrl;
      if (shareBanner) shareBanner.style.display = 'flex';
      // Show badge if we know the repo
      var repo = data.repo || '';
      if (repo && document.getElementById('badge-section')) {
        var badgeMd = '[![Verilay Score](https://verilay.dev/badge/' + repo + ')](https://verilay.dev/report/' + result.report_id + ')';
        document.getElementById('badge-code').value = badgeMd;
        document.getElementById('badge-section').style.display = 'block';
      }
    }
  } catch(e) {
    console.log('Auto-save failed silently:', e);
  }
}

async function saveReport() {
  var btn = document.getElementById('btn-save-report');
  if (!btn) return;
  btn.textContent = 'Saving...';
  btn.disabled = true;

  try {
    // Collect all current data
    var reportData = Object.assign({}, currentReport || {});
    reportData.layers = Object.values(currentLayers);
    if (window._step4Data) {
      reportData.top_fixes = window._step4Data.top_fixes || [];
      reportData.second_opinion = window._step4Data.second_opinion || {};
      reportData.security_score = window._step4Data.security_score || {};
    }

    var resp = await fetch('/save-report', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(reportData)
    });
    var data = await resp.json();
    if (data.report_id) {
      savedReportId = data.report_id;
      var shareUrl = window.location.origin + '/report/' + data.report_id;
      document.getElementById('share-url').value = shareUrl;
      document.getElementById('share-banner').style.display = 'flex';
      btn.innerHTML = '<i class="ti ti-check" style="font-size:12px"></i> Saved';
      btn.style.color = 'var(--grt)';
    }
  } catch(e) {
    btn.textContent = 'Save failed';
    btn.disabled = false;
  }
}

function exportMarkdown() {
  if (!savedReportId) {
    // Save first then download
    saveReport().then(function() {
      setTimeout(function() {
        if (savedReportId) {
          window.location.href = '/export/markdown/' + savedReportId;
        }
      }, 1000);
    });
    return;
  }
  window.location.href = '/export/markdown/' + savedReportId;
}

// ── Analysis History (localStorage) ──────────────────────────────────────────
var HISTORY_KEY = 'verilay_history';
var MAX_HISTORY = 10;

function saveToHistory(report) {
  try {
    var history = getHistory();
    var resolvedId = report._savedId || savedReportId || '';
    console.log('[History] Saving with id:', resolvedId, 'repo:', report.repo);
    var entry = {
      id: resolvedId,
      repo: report.repo || 'Unknown',
      score: (report.health || {}).score || '?',
      verdict: (report.prod_ready || {}).verdict || 'needs_work',
      summary: report.summary || '',
      built_with: report.built_with || '',
      critical: (report.health || {}).critical || 0,
      warnings: (report.health || {}).warnings || 0,
      timestamp: new Date().toISOString(),
      method: report.input_method || 'github'
    };
    // Remove duplicate if same repo
    history = history.filter(function(h) { return h.repo !== entry.repo; });
    history.unshift(entry);
    if (history.length > MAX_HISTORY) history = history.slice(0, MAX_HISTORY);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    renderHistory();
  } catch(e) {
    console.log('History save failed:', e);
  }
}

function getHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
  } catch(e) { return []; }
}

function clearHistory() {
  localStorage.removeItem(HISTORY_KEY);
  renderHistory();
}

function renderHistory() {
  var history = getHistory();
  var section = document.getElementById('history-section');
  var list = document.getElementById('history-list');
  if (!section || !list) return;

  if (history.length === 0) {
    section.style.display = 'none';
    return;
  }

  section.style.display = 'block';
  var showMoreBtn = document.getElementById('history-show-more');
  if (showMoreBtn) showMoreBtn.style.display = history.length > 2 ? 'block' : 'none';
  var verdictColors = {
    ready: 'var(--grl):var(--grt)',
    needs_work: 'var(--orl):var(--ort)',
    not_ready: 'var(--rdl):var(--rdt)'
  };
  var scoreColors = {A:'#1D9E75',B:'#4A90D9',C:'#EF9F27',D:'#E24B4A',F:'#A32D2D'};

  list.innerHTML = history.map(function(h, idx) {
    var vc = (verdictColors[h.verdict] || verdictColors.needs_work).split(':');
    var sc = scoreColors[h.score] || '#999';
    var date = new Date(h.timestamp);
    var timeStr = date.toLocaleDateString('en-AU', {day:'numeric',month:'short'}) +
                  ' ' + date.toLocaleTimeString('en-AU', {hour:'2-digit',minute:'2-digit'});
    var isLatest = idx === 0;
    var isHidden = idx >= 2;
    return '<div class="history-item" style="display:' + (isHidden ? 'none' : 'flex') + ';background:var(--sur);border:0.5px solid ' + (isLatest ? 'var(--pu)' : 'var(--bdr)') + ';border-radius:var(--r);padding:.65rem .9rem;align-items:center;gap:10px;cursor:pointer" ' +
           'onclick="viewFromHistory(' + idx + ')" title="View report">' +
           '<div style="width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff;flex-shrink:0;background:' + sc + '">' + h.score + '</div>' +
           '<div style="flex:1;min-width:0">' +
           '<div style="font-size:12px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + (isLatest ? '<span style="font-size:9px;background:var(--pu);color:#fff;border-radius:10px;padding:1px 6px;margin-right:5px;font-weight:600">LATEST</span>' : '') + esc(h.repo) + '</div>' +
           '<div style="font-size:11px;color:var(--mut)">' + timeStr + ' &nbsp;·&nbsp; ' + h.critical + ' critical, ' + h.warnings + ' warnings</div>' +
           '</div>' +
           '<div style="display:flex;gap:6px;flex-shrink:0">' +
           '<button onclick="event.stopPropagation();viewFromHistory(' + idx + ')" style="font-size:11px;padding:3px 9px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);cursor:pointer">View</button>' +

           '</div>' +
           '</div>';
  }).join('');
}

function rerunFromHistory(idx) {
  var history = getHistory();
  var entry = history[idx];
  if (!entry) return;
  showForm();
  // Switch to correct method
  var method = entry.method || 'github';
  currentMethod = method;
  document.querySelectorAll('.mc').forEach(function(c) { c.classList.remove('sel'); });
  var mc = document.getElementById('mc-' + method);
  if (mc) mc.classList.add('sel');
  document.querySelectorAll('.ip').forEach(function(p) { p.classList.remove('vis'); });
  var panel = document.getElementById('p-' + method);
  if (panel) panel.classList.add('vis');
  // Pre-fill the input
  if (method === 'github') {
    var input = document.getElementById('gh-url');
    if (input) input.value = 'https://github.com/' + entry.repo;
  } else if (method === 'url') {
    var input2 = document.getElementById('lu');
    if (input2) input2.value = entry.repo;
  }
  window.scrollTo({top: 0, behavior: 'smooth'});
}

function viewFromHistory(idx) {
  var history = getHistory();
  var entry = history[idx];
  if (!entry) return;
  if (entry.id) {
    // Open saved report in new tab
    window.open('/report/' + entry.id, '_blank');
  } else {
    alert('This report was not saved. Run a new analysis from the form.');
  }
}

function init() {
  // Method cards
  ['github','zip','url'].forEach(function(m) {
    var el = document.getElementById('mc-' + m);
    if (el) {
      el.addEventListener('click', function() {
        currentMethod = m;
        document.querySelectorAll('.mc').forEach(function(c) { c.classList.remove('sel'); });
        el.classList.add('sel');
        document.querySelectorAll('.ip').forEach(function(p) { p.classList.remove('vis'); });
        var panel = document.getElementById('p-' + m);
        if (panel) panel.classList.add('vis');
      });
    }
  });

  // History
  renderHistory();
  var btnClearHistory = document.getElementById('btn-clear-history');
  if (btnClearHistory) btnClearHistory.addEventListener('click', clearHistory);

  // Load analysis count for social proof
  setTimeout(function() {
    fetch('/stats').then(function(r) { return r.json(); }).then(function(d) {
      var badge = document.getElementById('analysis-count-badge');
      var countEl = document.getElementById('analysis-count');
      if (badge && countEl && d.analyses > 0) {
        countEl.textContent = d.formatted || d.analyses;
        badge.style.display = 'block';
        badge.style.visibility = 'visible';
        badge.style.opacity = '1';
      }
    }).catch(function(e) { console.log('Stats fetch failed:', e); });
  }, 500);

  // Analyse button
  var btnAnalyse = document.getElementById('btn-analyse');
  if (btnAnalyse) btnAnalyse.addEventListener('click', runAnalysis);

  // New analysis buttons
  var btnNew = document.getElementById('btn-new');
  if (btnNew) btnNew.addEventListener('click', function() { resetForm(true); });
  var btnNew2 = document.getElementById('btn-new2');
  if (btnNew2) btnNew2.addEventListener('click', function() { resetForm(false); });

  // Save report / share link
  var btnSave = document.getElementById('btn-save-report');
  if (btnSave) btnSave.addEventListener('click', saveReport);

  // Copy share URL button
  var btnCopyShare = document.getElementById('btn-copy-share');
  if (btnCopyShare) btnCopyShare.addEventListener('click', function() {
    var url = document.getElementById('share-url').value;
    navigator.clipboard.writeText(url).then(function() {
      btnCopyShare.textContent = '✓ Copied!';
      setTimeout(function() { btnCopyShare.textContent = 'Copy link'; }, 2000);
    });
  });

  // Export markdown
  var btnMd = document.getElementById('btn-export-md');
  if (btnMd) btnMd.addEventListener('click', exportMarkdown);

  // Print / PDF
  var btnPrint = document.getElementById('btn-print');
  if (btnPrint) btnPrint.addEventListener('click', function() { window.print(); });

  // Part 2 buttons
  var btnP2 = document.getElementById('btn-p2');
  if (btnP2) btnP2.addEventListener('click', runPart2);
  var btnSkip = document.getElementById('btn-skip');
  if (btnSkip) btnSkip.addEventListener('click', function() {
    document.getElementById('p2-banner').style.display = 'none';
  });

  // File input
  var zf = document.getElementById('zf');
  if (zf) zf.addEventListener('change', function() {
    var name = this.files[0] ? this.files[0].name : '';
    document.getElementById('fn').textContent = name ? '✓ ' + name : '';
  });

  // Hero buttons - show form
  function showForm() {
    document.getElementById('hero-section').style.display = 'none';
    document.getElementById('form-section').style.display = 'block';
    renderHistory();
    window.scrollTo(0,0);
  }
  function showHero() {
    document.getElementById('hero-section').style.display = 'block';
    document.getElementById('form-section').style.display = 'none';
    window.scrollTo(0,0);
  }

  ['btn-start-hero','btn-hero-analyse','btn-hero-cta'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('click', showForm);
  });

  var backBtn = document.getElementById('btn-back-hero');
  if (backBtn) backBtn.addEventListener('click', showHero);

  // Sample modal
  var btnDemo = document.getElementById('btn-hero-demo');
  if (btnDemo) btnDemo.addEventListener('click', function() {
    document.getElementById('sample-modal').style.display = 'block';
    document.body.style.overflow = 'hidden';
  });
  var btnClose = document.getElementById('btn-close-modal');
  if (btnClose) btnClose.addEventListener('click', function() {
    document.getElementById('sample-modal').style.display = 'none';
    document.body.style.overflow = '';
  });
  var btnModalCta = document.getElementById('btn-modal-cta');
  if (btnModalCta) btnModalCta.addEventListener('click', function() {
    document.getElementById('sample-modal').style.display = 'none';
    document.body.style.overflow = '';
    showForm();
  });
  // Close modal on backdrop click
  var modal = document.getElementById('sample-modal');
  if (modal) modal.addEventListener('click', function(e) {
    if (e.target === modal) {
      modal.style.display = 'none';
      document.body.style.overflow = '';
    }
  });

  // Drag and drop
  var dz = document.getElementById('dz');
  if (dz) {
    dz.addEventListener('dragover', function(e) { e.preventDefault(); dz.style.borderColor = 'var(--pu)'; });
    dz.addEventListener('dragleave', function() { dz.style.borderColor = ''; });
    dz.addEventListener('drop', function(e) {
      e.preventDefault(); dz.style.borderColor = '';
      var f = e.dataTransfer.files[0];
      if (f) {
        document.getElementById('zf').files = e.dataTransfer.files;
        document.getElementById('fn').textContent = '✓ ' + f.name;
      }
    });
  }
}

function showErr(msg) {
  var el = document.getElementById('eb');
  el.textContent = msg;
  el.classList.add('vis');
}
function hideErr() {
  document.getElementById('eb').classList.remove('vis');
}

var steps = [
  {msg: 'Reading your project files...', sub: 'Fetching from GitHub API', pct: 10},
  {msg: 'Detecting your tech stack...', sub: 'Identifying frameworks and libraries', pct: 25},
  {msg: 'Analysing each layer...', sub: 'Auth, Database, API, Frontend...', pct: 50},
  {msg: 'Running security checks...', sub: 'Looking for exposed secrets and issues', pct: 70},
  {msg: 'Writing plain-English explanations...', sub: 'Translating technical findings', pct: 90},
];
var stepIdx = 0, stepTimer = null, etaTimer = null, elapsedSecs = 0;

function setStep(i) {
  stepIdx = i;
  var s = steps[i] || steps[steps.length-1];
  document.getElementById('lm').textContent = s.msg;
  document.getElementById('ls').textContent = s.sub;

  // Update progress bar
  var bar = document.getElementById('prog-bar');
  var pct = document.getElementById('prog-pct');
  if (bar) bar.style.width = s.pct + '%';
  if (pct) pct.textContent = s.pct + '%';

  // Update step icons
  for (var j = 0; j < steps.length; j++) {
    var stepEl = document.getElementById('step-' + j);
    if (!stepEl) continue;
    var icon = stepEl.querySelector('.step-icon');
    if (!icon) continue;
    if (j < i) {
      // Completed
      icon.style.background = 'var(--gr)';
      icon.style.borderColor = 'var(--gr)';
      icon.style.color = '#fff';
      icon.textContent = '✓';
      stepEl.querySelector('span').style.color = 'var(--grt)';
    } else if (j === i) {
      // Active
      icon.style.background = 'var(--pul)';
      icon.style.borderColor = 'var(--pu)';
      icon.style.color = 'var(--put)';
      icon.textContent = (j+1).toString();
      stepEl.querySelector('span').style.color = 'var(--put)';
      stepEl.querySelector('span').style.fontWeight = '500';
    } else {
      // Pending
      icon.style.background = '';
      icon.style.borderColor = 'var(--bdr)';
      icon.style.color = 'var(--mut)';
      icon.textContent = (j+1).toString();
      stepEl.querySelector('span').style.color = 'var(--mut)';
      stepEl.querySelector('span').style.fontWeight = '';
    }
  }
}

function updateEta() {
  elapsedSecs++;
  var remaining = Math.max(5, 35 - elapsedSecs);
  var eta = document.getElementById('prog-eta');
  if (eta) {
    if (remaining > 10) eta.textContent = '~' + remaining + ' seconds remaining';
    else if (remaining > 0) eta.textContent = 'Almost done...';
    else eta.textContent = 'Finalising...';
  }
}

function startMsgs() {
  stepIdx = 0;
  elapsedSecs = 0;
  setStep(0);

  // Reset all steps to pending
  for (var j = 0; j < steps.length; j++) {
    var stepEl = document.getElementById('step-' + j);
    if (stepEl) {
      var icon = stepEl.querySelector('.step-icon');
      if (icon) {
        icon.style.background = '';
        icon.style.borderColor = 'var(--bdr)';
        icon.style.color = 'var(--mut)';
        icon.textContent = (j+1).toString();
      }
      var span = stepEl.querySelector('span');
      if (span) { span.style.color = 'var(--mut)'; span.style.fontWeight = ''; }
    }
  }

  // Advance steps on a timer
  var stepTimes = [0, 5000, 12000, 20000, 27000];
  stepTimes.forEach(function(t, i) {
    setTimeout(function() {
      if (stepIdx >= 0) setStep(i);
    }, t);
  });

  // ETA countdown
  etaTimer = setInterval(updateEta, 1000);
}

function stopMsgs() {
  stepIdx = -1;
  if (etaTimer) clearInterval(etaTimer);
  // Complete the bar
  var bar = document.getElementById('prog-bar');
  var pct = document.getElementById('prog-pct');
  var eta = document.getElementById('prog-eta');
  if (bar) bar.style.width = '100%';
  if (pct) pct.textContent = '100%';
  if (eta) eta.textContent = 'Complete!';
  // Mark all steps done
  for (var j = 0; j < steps.length; j++) {
    var stepEl = document.getElementById('step-' + j);
    if (!stepEl) continue;
    var icon = stepEl.querySelector('.step-icon');
    if (icon) {
      icon.style.background = 'var(--gr)';
      icon.style.borderColor = 'var(--gr)';
      icon.style.color = '#fff';
      icon.textContent = '✓';
    }
    var span = stepEl.querySelector('span');
    if (span) { span.style.color = 'var(--grt)'; }
  }
}

async function runAnalysis() {
  hideErr();
  var fd = new FormData();
  fd.append('method', currentMethod);
  if (currentMethod === 'github') {
    var url = document.getElementById('gh-url').value.trim();
    if (!url) { showErr('Please enter a GitHub URL'); return; }
    fd.append('github_url', url);
  } else if (currentMethod === 'zip') {
    var f = document.getElementById('zf').files[0];
    if (!f) { showErr('Please select a ZIP file'); return; }
    fd.append('zip_file', f);
  } else {
    var url = document.getElementById('lu').value.trim();
    if (!url) { showErr('Please enter a URL'); return; }
    fd.append('live_url', url);
  }
  document.getElementById('form-section').style.display = 'none';
  document.getElementById('ld').classList.add('vis');
  startMsgs();
  try {
    var resp = await fetch('/analyse-stream', { method: 'POST', body: fd });
    if (!resp.ok) { throw new Error('Server error ' + resp.status); }
    var reader = resp.body.getReader();
    var decoder = new TextDecoder();
    var buffer = '';
    while (true) {
      var chunk = await reader.read();
      if (chunk.done) break;
      buffer += decoder.decode(chunk.value, {stream: true});
      var nlines = buffer.split('\n');
      buffer = nlines.pop();
      for (var i = 0; i < nlines.length; i++) {
        var line = nlines[i];
        line = line.trim();
        if (!line) continue;
        try { handleStreamEvent(JSON.parse(line)); }
        catch(e) { console.warn('Stream parse error:', line); }
      } // end for
    }
  } catch(e) {
    stopMsgs();
    document.getElementById('ld').classList.remove('vis');
    document.getElementById('form-section').style.display = 'block';
    var errMsg = e.message || 'Something went wrong. Please try again.';
    // Make network errors more helpful
    if (errMsg.includes('Failed to fetch') || errMsg.includes('NetworkError') || errMsg.includes('Load failed')) {
      errMsg = 'Connection interrupted. This can happen with large repos — please try again. If the issue persists, try a smaller repo or ZIP upload.';
    } else if (errMsg.includes('504') || errMsg.includes('timeout')) {
      errMsg = 'Analysis timed out — the repo may be too large. Try a ZIP upload with just the main source files.';
    } else if (errMsg.includes('503')) {
      errMsg = 'Server is busy — please wait 30 seconds and try again.';
    }
    showErr(errMsg);
  }
}

function handleStreamEvent(evt) {
  switch(evt.event) {
    case 'status':
      document.getElementById('lm').textContent = evt.data;
      break;
    case 'step1':
      stopMsgs();
      document.getElementById('ld').classList.remove('vis');
      currentReport = evt.data;
      renderReport(evt.data);
      // Track analysis completion in Plausible
      if (window.plausible) {
        plausible('Analysis Complete', {props: {
          method: evt.data.input_method || 'github',
          score: (evt.data.health || {}).score || 'unknown',
          built_with: evt.data.built_with ? evt.data.built_with.split(' ')[0] : 'unknown'
        }});
      }
      break;
    case 'step2':
    case 'step3':
      if (evt.data && evt.data.layers) appendLayers(evt.data.layers);
      window._analysisComplete = true;  // All layers loaded
      break;
    case 'step2_error':
    case 'step3_error':
      showLayerError('Layer analysis error: ' + evt.data);
      break;
    case 'saved':
      savedReportId = evt.data.report_id;
      currentVerifications = {};  // Reset verifications for new report
      // Save to history with the report ID
      if (currentReport) {
        var reportForHistory = Object.assign({}, currentReport);
        reportForHistory._savedId = savedReportId;
        saveToHistory(reportForHistory);
      }
      var shareUrl = window.location.origin + '/report/' + savedReportId;
      var shareInput = document.getElementById('share-url');
      var shareBanner = document.getElementById('share-banner');
      var statusEl = document.getElementById('report-status');
      if (shareInput) shareInput.value = shareUrl;
      if (shareBanner) shareBanner.style.display = 'flex';
      // Add delete button to share banner
      var deleteBtn = document.getElementById('delete-report-btn');
      if (deleteBtn) deleteBtn.style.display = 'inline-block';

      // Show waitlist nudge after 3+ analyses
      var analysisCount = parseInt(localStorage.getItem('verilay_analysis_count') || '0') + 1;
      localStorage.setItem('verilay_analysis_count', analysisCount);
      if (analysisCount >= 3 && !localStorage.getItem('verilay_waitlist_shown')) {
        setTimeout(function() { showWaitlistNudge(analysisCount); }, 2000);
      }
      // Show feedback widget and star prompt
      var fw = document.getElementById('feedback-widget');
      if (fw) fw.style.display = 'block';
      var sp = document.getElementById('star-prompt');
      if (sp) sp.style.display = 'block';
      if (statusEl) statusEl.textContent = 'Report saved';
      var repo = currentReport ? currentReport.repo : '';
      if (repo && document.getElementById('badge-section')) {
        document.getElementById('badge-code').value =
          '[![Verilay Score](https://verilay.dev/badge/' + repo + ')](https://verilay.dev/report/' + savedReportId + ')';
        document.getElementById('badge-section').style.display = 'block';
      }
      break;
    case 'layers_complete':
      var lb = document.getElementById('steps23-loading');
      if (lb) lb.style.display = 'none';
      var p2 = document.getElementById('p2-banner');
      if (p2) p2.style.display = 'block';
      break;
    case 'error':
      stopMsgs();
      if (document.getElementById('ld').classList.contains('vis')) {
        document.getElementById('ld').classList.remove('vis');
        document.getElementById('form-section').style.display = 'block';
        showErr(evt.data);
      } else {
        showLayerError(evt.data);
      }
      break;
  }
}


function updateStepsLabel(msg) {
  var el = document.getElementById('steps23-msg');
  if (el) el.textContent = msg;
}

function resetForm(goToForm) {
  // Clear the report
  document.getElementById('rpt').classList.remove('vis');
  if (document.getElementById('report-content'))
    document.getElementById('report-content').innerHTML = '';
  if (document.getElementById('p2-banner'))
    document.getElementById('p2-banner').style.display = 'none';
  if (document.getElementById('p2-loading'))
    document.getElementById('p2-loading').style.display = 'none';
  if (document.getElementById('p2-results'))
    document.getElementById('p2-results').innerHTML = '';
  var s23 = document.getElementById('steps23-loading');
  if (s23) s23.style.display = 'none';
  var lc = document.getElementById('layers-container');
  if (lc) lc.innerHTML = '';

  // Reset state
  currentReport = null;
  currentLayers = {};
  activeLayer = null;
  activeMode = 'expert';
  savedReportId = null;

  // Navigate
  if (goToForm) {
    // Go straight to form — skip hero
    document.getElementById('hero-section').style.display = 'none';
    document.getElementById('form-section').style.display = 'block';
    renderHistory();
    window.scrollTo({top: 0, behavior: 'smooth'});
  } else {
    // Go back to hero page
    document.getElementById('hero-section').style.display = 'block';
    document.getElementById('form-section').style.display = 'none';
    window.scrollTo({top: 0, behavior: 'smooth'});
  }
}

function catColors(cat) {
  var m = {frontend:'#EEEDFE:#3C3489',backend:'#E1F5EE:#085041',database:'#E1F5EE:#0F6E56',auth:'#FAECE7:#712B13',styling:'#F1EFE8:#444441',build:'#FAEEDA:#633806',testing:'#E6F1FB:#0C447C',other:'#F1EFE8:#5F5E5A'};
  return (m[cat] || m.other).split(':');
}
function sevStyle(s) {
  var m = {critical:'background:var(--rdl);color:var(--rdt)',warning:'background:var(--orl);color:var(--ort)',passing:'background:var(--grl);color:var(--grt)',info:'background:var(--bll);color:var(--blt)'};
  return m[s] || m.info;
}
function sevIcon(s) {
  return {critical:'ti-alert-circle',warning:'ti-alert-triangle',passing:'ti-circle-check',info:'ti-info-circle'}[s] || 'ti-info-circle';
}
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function renderReport(data) {
  currentReport = data;
  // Load verifications from saved report data
  if (data.verifications) {
    currentVerifications = data.verifications;
  }
  currentFilesSample = data.files_sample || '';
  currentLayers = {};
  (data.layers || []).forEach(function(l) { currentLayers[l.name] = l; });

  var isSurf = data.analysis_depth === 'surface';
  var h = data.health || {};
  // Client-side score correction — ensures score matches actual counts
  var critical = parseInt(h.critical || 0);
  var warnings = parseInt(h.warnings || 0);
  if (critical === 0 && warnings === 0) h.score = 'A';
  else if (critical === 0 && warnings <= 3) h.score = 'B';
  else if (critical <= 2) { if (h.score === 'D' || h.score === 'F') {} else h.score = 'C'; }
  var pr = data.prod_ready || {};

  var pbMap = {
    ready: ['#EAF3DE','#27500A','ti-circle-check','Production ready'],
    needs_work: ['#FAEEDA','#633806','ti-alert-triangle','Needs work before going live'],
    not_ready: ['#FCEBEB','#A32D2D','ti-alert-circle','Not production ready']
  };
  var pb = pbMap[pr.verdict] || pbMap.needs_work;

  var html = '';

  if (isSurf) {
    html += '<div style="background:var(--orl);border-radius:var(--r);padding:.85rem 1rem;margin-bottom:10px;font-size:12px;color:var(--ort)"><strong>Surface scan only.</strong> Use GitHub or ZIP for a full analysis.</div>';
  }

  html += '<div class="prod-banner" style="background:' + pb[0] + ';color:' + pb[1] + '">';
  html += '<i class="ti ' + pb[2] + '" style="font-size:26px"></i>';
  html += '<div style="flex:1"><div style="font-size:15px;font-weight:600;margin-bottom:2px">' + pb[3] + '</div>';
  html += '<div style="font-size:12px;opacity:.85">' + esc(pr.reason||'') + '</div></div>';
  if (data.prev_score && data.prev_score !== h.score) {
    var scores = ['F','D','C','B','A'];
    var prevIdx = scores.indexOf(data.prev_score);
    var currIdx = scores.indexOf(h.score);
    if (currIdx > prevIdx) {
      html += '<div style="background:#1D9E75;color:#fff;border-radius:20px;padding:4px 12px;font-size:12px;font-weight:600;white-space:nowrap">▲ ' + data.prev_score + ' → ' + h.score + ' Improved!</div>';
    } else if (currIdx < prevIdx) {
      html += '<div style="background:#E24B4A;color:#fff;border-radius:20px;padding:4px 12px;font-size:12px;font-weight:600;white-space:nowrap">▼ ' + data.prev_score + ' → ' + h.score + '</div>';
    }
  }
  html += '</div>';

  // Static site recommendation
  var pr = data.prod_ready || {};
  if (pr.static_recommendation === 'yes' || pr.static_recommendation === 'partial') {
    html += '<div style="background:#EFF6FF;border:0.5px solid #3B82F6;border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px;display:flex;align-items:flex-start;gap:10px">';
    html += '<i class="ti ti-topology-star" style="color:#3B82F6;font-size:16px;margin-top:1px;flex-shrink:0"></i>';
    html += '<div>';
    html += '<div style="font-size:13px;font-weight:600;color:#1D4ED8;margin-bottom:2px">💡 Could this be a static site?</div>';
    if (pr.static_recommendation === 'yes') {
      html += '<div style="font-size:12px;color:#1D4ED8;line-height:1.55">' + esc(pr.static_reason || 'This app may not need a database or server — it could be simpler and cheaper to host as a static site on Netlify or Vercel for free.') + '</div>';
    } else {
      html += '<div style="font-size:12px;color:#1D4ED8;line-height:1.55">' + esc(pr.static_reason || 'Parts of this app could potentially be simplified. A static approach would reduce complexity and security risk.') + '</div>';
    }
    html += '</div></div>';
  }

  // Scope notice - always shown, sets honest expectations
  html += '<div style="background:var(--bg);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px;display:flex;align-items:flex-start;gap:10px">';
  html += '<i class="ti ti-info-circle" style="font-size:16px;color:var(--mut);flex-shrink:0;margin-top:1px"></i>';
  html += '<div style="font-size:12px;color:var(--mut);line-height:1.55">';
  html += '<strong style="color:var(--txt)">What Verilay covers:</strong> This is a first-pass overview of your codebase - great for understanding what was built and catching obvious issues. ';
  html += 'For apps handling real users or sensitive data, we recommend a deeper review: ';
  html += '<a href="https://snyk.io" target="_blank" style="color:var(--pu);text-decoration:underline">Snyk</a> for dependency vulnerabilities, ';
  html += '<a href="https://coderabbit.ai" target="_blank" style="color:var(--pu);text-decoration:underline">CodeRabbit</a> for code review, ';
  html += 'or a developer security audit before going live with real user data.';
  html += '</div></div>';

  // Ask AI button
  html += '<div style="margin:.75rem 0;padding:.85rem 1rem;background:var(--pul);border:0.5px solid var(--pu);border-radius:var(--r);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">';
  html += '<div>';
  html += '<div style="font-size:13px;font-weight:600;color:var(--put);margin-bottom:2px">🤖 Confused about a finding?</div>';
  html += '<div style="font-size:12px;color:var(--put)">Ask AI to explain any issue in plain English and suggest how to fix it in your specific app.</div>';
  html += '</div>';
  html += '<div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px">';
  html += '<button onclick="askAIAboutReport()" style="font-size:12px;padding:7px 16px;border-radius:20px;background:var(--pu);color:#fff;border:none;cursor:pointer;white-space:nowrap;font-weight:500">Ask AI about this report →</button>';
  html += '<span style="font-size:10px;color:var(--put);opacity:.7">Free Claude.ai account required</span>';
  html += '</div>';
  html += '</div>';

  var pills = (data.stack||[]).map(function(s) {
    var c = catColors(s.category);
    return '<span class="pill" style="background:' + c[0] + ';color:' + c[1] + '">' + esc(s.name||'') + ' ' + esc(s.version||'') + '</span>';
  }).join('');

  var hvals = [h.critical||0, h.warnings||0, h.passing||0, h.score||'?'];
  var hlbls = ['critical','warnings','passing','score'];
  var hcols = [['var(--rdl)','var(--rdt)'],['var(--orl)','var(--ort)'],['var(--grl)','var(--grt)'],['var(--bll)','var(--blt)']];
  var hcards = hvals.map(function(v,i) {
    return '<div class="hc" style="background:' + hcols[i][0] + '"><div style="font-size:18px;font-weight:600;color:' + hcols[i][1] + '">' + v + '</div><div style="font-size:10px;color:' + hcols[i][1] + ';margin-top:1px">' + hlbls[i] + '</div></div>';
  }).join('');

  html += '<div class="rh">';
  html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">';
  html += '<div style="font-size:16px;font-weight:600">' + esc(data.repo||'') + '</div>';
  html += '<span style="font-size:10px;background:var(--pu);color:#fff;border-radius:10px;padding:2px 8px;font-weight:600">Current</span>';
  html += '</div>';
  html += '<div style="font-size:12px;color:var(--mut);margin-bottom:.65rem">' + esc(data.built_with||'') + '  .  ' + (data.files_read||0) + ' files  .  ' + (data.generated_at||'') + '</div>';
  html += '<div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:.65rem">' + pills + '</div>';
  html += '<div class="hg">' + hcards + '</div></div>';

  // Realistic score guide for vibe-coded apps
  if (h.score && h.score !== 'A') {
    var scoreMsg = '';
    var scoreBg = '';
    var scoreBdr = '';
    if (h.score === 'A') {
      scoreBg = '#F0FDF4'; scoreBdr = '#1D9E75';
      scoreMsg = '🏆 <strong>Score A — Excellent.</strong> Your app has no critical or warning findings. This is outstanding — most AI-built apps score B or C. Keep dependencies updated and review your security posture as you add new features.';
    } else if (h.score === 'B') {
      scoreBg = '#EFF6FF'; scoreBdr = '#4A90D9';
      scoreMsg = '🎯 <strong>Score B — Safe to launch.</strong> This is the realistic target for AI-built apps. ' +
        'A score requires developer-level hardening that goes beyond what AI builders can do automatically.<br><br>' +
        '<strong>To reach A, verify these with your AI builder:</strong><br>' +
        '✓ RLS enabled on all Supabase tables<br>' +
        '✓ No secrets or API keys in frontend code<br>' +
        '✓ All protected routes have auth middleware<br>' +
        '✓ Dependencies have no critical vulnerabilities<br>' +
        '✓ Webhook endpoints validate signatures<br>' +
        '✓ Payment endpoints properly scoped';
    } else if (h.score === 'C') {
      scoreBg = '#FEF9C3'; scoreBdr = '#EAB308';
      scoreMsg = '🎯 <strong>Score C — Almost there.</strong> Fix the critical issues above and you will reach B. ' +
        'That is the realistic goal for AI-built apps — not A.<br><br>' +
        '<strong>Your path to B:</strong><br>' +
        '1. Use the advice prompts below to investigate each critical finding<br>' +
        '2. Take findings to your AI builder and ask them to verify<br>' +
        '3. Paste their response back here to update your score<br>' +
        '4. Once all criticals are verified or fixed — re-run for updated score';
    } else if (h.score === 'D' || h.score === 'F') {
      scoreBg = '#FEF2F2'; scoreBdr = '#EF4444';
      scoreMsg = '🎯 <strong>Score ' + h.score + ' — Not ready to launch.</strong> Fix critical issues first using the fix prompts below. Realistic goal is B — safe for real users. Getting to A requires a professional developer security review.';
    }
    if (scoreMsg) {
      html += '<div style="background:' + scoreBg + ';border:0.5px solid ' + scoreBdr + ';border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px;font-size:12px;line-height:1.6">' + scoreMsg + '</div>';
    }
  }

  html += '<div class="tabs" id="main-tabs">';
  html += '<button class="tab on" data-tab="layers">Layer map</button>';
  html += '<button class="tab" data-tab="stack">Full stack</button>';
  html += '</div>';

  var icons = {Auth:'ti-shield',Database:'ti-database',Config:'ti-lock',Frontend:'ti-layout',Libraries:'ti-package',API:'ti-api','File Handling':'ti-file'};
  var sdot = {critical:'#E24B4A',warning:'#EF9F27',passing:'#639922'};
  var sibg = {critical:'var(--rdl)',warning:'var(--orl)',passing:'var(--grl)'};
  var siclr = {critical:'var(--rdt)',warning:'var(--ort)',passing:'var(--grt)'};

  var lbtns = (data.layers||[]).map(function(l) {
    return '<button class="lb" data-layer="' + esc(l.name) + '">' +
      '<div class="lico" style="background:' + (sibg[l.status]||sibg.passing) + ';color:' + (siclr[l.status]||siclr.passing) + '"><i class="ti ' + (icons[l.name]||'ti-code') + '"></i></div>' +
      '<span style="flex:1">' + esc(l.name) + '</span>' +
      '<div class="ldot" style="background:' + (sdot[l.status]||sdot.passing) + '"></div>' +
      '</button>';
  }).join('');

  html += '<div class="panel on" id="p-layers">';
  html += '<div class="ll">';
  html += '<div class="lnav" id="layer-nav">';
  html += '<div id="layers-loading" style="font-size:11px;color:var(--mut);padding:.5rem .25rem;display:flex;align-items:center;gap:6px">';
  html += '<div style="width:14px;height:14px;border:2px solid var(--pul);border-top-color:var(--pu);border-radius:50%;animation:sp 1s linear infinite;flex-shrink:0"></div>';
  html += 'Loading layers...</div>';
  html += lbtns;
  html += '</div>';
  html += '<div class="ca">';
  html += '<div id="mode-toggle" class="mt" style="display:none">';
  html += '<button class="mb on" data-mode="expert">Expert</button>';
  html += '<button class="mb" data-mode="learner">Learner</button>';
  html += '</div>';
  // Only show spinner if no layers loaded yet
  var hasLayers = data.layers && data.layers.length > 0;
  html += '<div id="layer-content" style="padding:.75rem 0">';
  if (!hasLayers) {
    html += '<div style="font-size:12px;color:var(--mut);display:flex;align-items:center;gap:8px">';
    html += '<div style="width:16px;height:16px;border:2px solid var(--pul);border-top-color:var(--pu);border-radius:50%;animation:sp 1s linear infinite;flex-shrink:0"></div>';
    html += 'Analysing your codebase - layers will appear shortly...</div>';
    html += '</div>';
  }
  html += '</div></div></div>';

  var scards = (data.stack||[]).map(function(s) {
    var c = catColors(s.category);
    return '<div class="sc"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:3px"><span style="font-size:12px;font-weight:500">' + esc(s.name||'') + '</span><span class="pill" style="font-size:10px;background:' + c[0] + ';color:' + c[1] + '">' + esc(s.category||'') + '</span></div><div style="font-size:11px;color:var(--mut);margin-bottom:2px">v' + esc(s.version||'?') + '</div><div style="font-size:11px;color:var(--mut);line-height:1.4">' + esc(s.plain_english||'') + '</div></div>';
  }).join('');
  html += '<div class="panel" id="p-stack"><div class="sg">' + scards + '</div></div>';

  document.getElementById('report-content').innerHTML = html;
  document.getElementById('rpt').classList.add('vis');

  // Wire New analysis buttons after report is rendered
  var btnNew = document.getElementById('btn-new');
  if (btnNew) {
    btnNew.onclick = null;
    btnNew.addEventListener('click', function() { resetForm(true); });
  }
  var btnNew2 = document.getElementById('btn-new2');
  if (btnNew2) {
    btnNew2.onclick = null;
    btnNew2.addEventListener('click', function() { resetForm(false); });
  }

  // Show surface scan notice for URL method
  var surfNotice = document.getElementById('surface-scan-notice');
  if (surfNotice) {
    surfNotice.style.display = (data.input_method === 'url' || isSurf) ? 'block' : 'none';
  }

  // Wire up tabs
  document.querySelectorAll('#main-tabs .tab').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#main-tabs .tab').forEach(function(b) { b.classList.remove('on'); });
      btn.classList.add('on');
      document.querySelectorAll('.panel').forEach(function(p) { p.classList.remove('on'); });
      var panel = document.getElementById('p-' + btn.dataset.tab);
      if (panel) panel.classList.add('on');
    });
  });

  // Wire up layer buttons
  document.querySelectorAll('#layer-nav .lb').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#layer-nav .lb').forEach(function(b) { b.classList.remove('act'); });
      btn.classList.add('act');
      activeLayer = btn.dataset.layer;
      renderLayer();
    });
  });

  // Wire up mode buttons
  document.querySelectorAll('#mode-toggle .mb').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#mode-toggle .mb').forEach(function(b) { b.classList.remove('on'); });
      btn.classList.add('on');
      activeMode = btn.dataset.mode;
      renderLayer();
    });
  });

  // Auto-select first layer
  var firstLayer = document.querySelector('#layer-nav .lb');
  if (firstLayer) firstLayer.click();

  // Part 2 banner only shown after layers_complete event fires
}

function renderLayer() {
  if (!activeLayer || !currentLayers[activeLayer]) return;
  var layer = currentLayers[activeLayer];
  var html = '';

  // Always show mode toggle when rendering a layer
  var mt = document.getElementById('mode-toggle');
  if (mt) mt.style.display = 'flex';

  // Mode toggle button wiring (re-wire every time layer changes)
  document.querySelectorAll('#mode-toggle .mb').forEach(function(btn) {
    btn.onclick = function() {
      document.querySelectorAll('#mode-toggle .mb').forEach(function(b) { b.classList.remove('on'); });
      btn.classList.add('on');
      activeMode = btn.dataset.mode;
      renderLayer();
    };
  });

  if (activeMode === 'expert') {
    var ex = layer.expert || {};
    html += '<div style="font-size:12px;color:var(--mut);margin-bottom:.75rem">' + esc(ex.summary||'') + '</div>';
    (ex.findings || []).forEach(function(f, fi) {
      html += '<div class="finding" style="' + sevStyle(f.severity) + '">';
      html += '<i class="ti ' + sevIcon(f.severity) + '" style="font-size:15px;flex-shrink:0;margin-top:1px"></i>';
      html += '<div><div style="font-weight:500;margin-bottom:2px">' + esc(f.title||'') + '</div>';
      html += '<div>' + esc(f.detail||'') + (f.file ? ' <code style="font-size:10px;opacity:.7">' + esc(f.file) + '</code>' : '') + '</div>';
      if (f.why_it_matters) html += '<div style="font-size:11px;margin-top:4px;opacity:.85"><strong>Why it matters:</strong> ' + esc(f.why_it_matters) + '</div>';
      // Add manual verification note for verify_jwt findings
      if (f.title && f.title.toLowerCase().indexOf('jwt') > -1) {
        html += '<div style="font-size:11px;margin-top:6px;padding:6px 8px;background:#FEF9C3;border-radius:6px;color:#854D0E">';
        html += '<strong>⚠️ Needs manual check:</strong> If your edge functions contain <code>getUser()</code> or <code>getClaims()</code> calls, this finding may not apply. ';
        html += 'Ask your AI builder: <em>"Do my edge functions validate auth in-code?"</em>';
        html += '</div>';
      }
      // Verify button for critical/warning findings
      if (f.severity === 'critical' || f.severity === 'warning') {
        var fKey = (activeLayer + '_' + fi).replace(/[^a-z0-9]/gi, '_').toLowerCase();
        var isVerified = currentVerifications && currentVerifications[fKey];
        if (isVerified) {
          html += '<div style="margin-top:8px;padding:6px 10px;background:#F0FDF4;border:0.5px solid #22C55E;border-radius:6px;font-size:11px;color:#166534">';
          html += '<strong>✅ Verified by AI builder</strong>';
          if (isVerified.verdict === 'false_positive') html += ' — confirmed not an issue';
          if (isVerified.verdict === 'fixed') html += ' — confirmed fixed';
          if (isVerified.builder_response) html += '<div style="margin-top:3px;opacity:.8;font-size:10px">' + esc(isVerified.builder_response.substring(0,120)) + (isVerified.builder_response.length > 120 ? '...' : '') + '</div>';
          html += '</div>';
        } else {
          html += '<div style="margin-top:8px">';
          var btnDisabled = !window._analysisComplete ? 'opacity:.4;cursor:not-allowed' : 'cursor:pointer';
          var btnClick = !window._analysisComplete ? '' : 'onclick="showVerifyPanel(\''+fKey+'\', this)"';
          var btnTitle = !window._analysisComplete ? 'title="Wait for full analysis to complete"' : '';
          html += '<button '+btnClick+' '+btnTitle+' style="font-size:11px;padding:4px 10px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);'+btnDisabled+'">✓ Mark as verified</button>';
          html += '<div id="verify-panel-'+fKey+'" style="display:none;margin-top:8px;background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.75rem">';
          html += '<div style="font-size:12px;font-weight:600;margin-bottom:4px">Paste your AI builder response:</div>';
          html += '<div style="font-size:11px;color:var(--mut);margin-bottom:6px">Take this finding to Lovable or Replit and ask them to verify it. Paste their response here.</div>';
          html += '<textarea id="verify-text-'+fKey+'" placeholder="Paste Lovable or Replit response here..." style="width:100%;height:70px;font-size:11px;padding:6px;border:0.5px solid var(--bdr);border-radius:6px;background:var(--bg);color:var(--txt);resize:vertical;box-sizing:border-box"></textarea>';
          html += '<div style="display:flex;gap:6px;margin-top:6px;flex-wrap:wrap">';
          html += '<button onclick="submitVerification(\''+fKey+'\', \'false_positive\')" style="font-size:11px;padding:4px 12px;border-radius:20px;background:#EFF6FF;color:#1D4ED8;border:0.5px solid #93C5FD;cursor:pointer">Already handled</button>';
          html += '<button onclick="submitVerification(\''+fKey+'\', \'fixed\')" style="font-size:11px;padding:4px 12px;border-radius:20px;background:#F0FDF4;color:#166534;border:0.5px solid #86EFAC;cursor:pointer">Fixed it</button>';
          html += '<button onclick="submitVerification(\''+fKey+'\', \'verified\')" style="font-size:11px;padding:4px 12px;border-radius:20px;background:var(--pul);color:var(--put);border:0.5px solid var(--pu);cursor:pointer">Verified — real issue</button>';
          html += '</div></div></div>';
        }
      }
      html += '</div></div>';
    });
  } else if (activeMode === 'learner') {
    var lrn = layer.learner || {};
    html += '<div class="learner-label"><i class="ti ti-school" style="font-size:11px"></i> Learner mode</div>';
    if (lrn.analogy) html += '<div class="analogy"><i class="ti ti-bulb" style="margin-right:5px"></i><strong>Think of it like this:</strong> ' + esc(lrn.analogy) + '</div>';
    html += '<div class="lc"><div class="lc-title">What is ' + esc(layer.name) + '?</div><div class="lc-body">' + esc(lrn.what_is_it||'') + '</div></div>';
    html += '<div class="lc"><div class="lc-title">In your app specifically</div><div class="lc-body">' + esc(lrn.what_it_does_in_your_app||'') + '</div></div>';
    if (lrn.how_it_connects) html += '<div class="lc"><div class="lc-title">How it connects to other layers</div><div class="lc-body">' + esc(lrn.how_it_connects) + '</div></div>';
    if (lrn.key_concept) html += '<div style="background:var(--pul);border-radius:8px;padding:.65rem .85rem;margin-bottom:8px;font-size:12px;color:var(--put)"><strong>Key concept:</strong> ' + esc(lrn.key_concept) + '</div>';
    (lrn.findings_plain || []).forEach(function(f) {
      html += '<div class="finding" style="' + sevStyle(f.severity) + '">';
      html += '<i class="ti ' + sevIcon(f.severity) + '" style="font-size:15px;flex-shrink:0;margin-top:1px"></i>';
      html += '<div><div style="font-weight:500;margin-bottom:2px">' + esc(f.plain_title||'') + '</div>';
      html += '<div>' + esc(f.plain_detail||'') + '</div>';
      if (f.real_world_impact) html += '<div style="font-size:11px;margin-top:4px;font-style:italic">' + esc(f.real_world_impact) + '</div>';
      if (f.action) html += '<div style="margin-top:5px;font-size:11px;font-weight:500">Action: ' + esc(f.action) + '</div>';
      // Learner mode — understand only, action happens in Expert mode
      if (f.severity === 'critical' || f.severity === 'warning') {
        html += '<div style="margin-top:10px;padding:8px 10px;background:var(--pul);border:0.5px solid var(--pu);border-radius:8px;font-size:11px;color:var(--put);line-height:1.55">';
        html += '<strong>💡 What to do next:</strong><br>';
        html += 'If you understand this finding and want to act on it — switch to <strong>Expert mode</strong> above to get an advice prompt you can take to your AI builder.<br><br>';
        html += '<em>Tip: Not sure what to do? Share this report with a developer or technical friend and ask them to review the Expert mode findings with you.</em>';
        html += '</div>';
      }
      html += '</div></div>';
    });

    // Quiz as optional collapsible at bottom of learner mode
    var quiz = layer.quiz || [];
    if (quiz.length > 0) {
      html += '<div style="margin-top:.85rem;border-top:0.5px solid var(--bdr);padding-top:.75rem">';
      html += '<button id="quiz-toggle" style="font-size:12px;font-weight:500;padding:5px 14px;border-radius:20px;border:0.5px solid var(--pu);background:transparent;color:var(--put);cursor:pointer;display:flex;align-items:center;gap:5px">';
      html += '<i class="ti ti-brain" style="font-size:13px"></i> Test your understanding (optional quiz)';
      html += '</button>';
      html += '<div id="quiz-content" style="display:none;margin-top:.65rem">';
      quiz.forEach(function(q, i) {
        html += '<div class="qcard" style="margin-bottom:7px"><div style="font-size:12px;font-weight:500;margin-bottom:.5rem">' + esc(q.question||'') + '</div>';
        var hasAnswer = q.answer && q.answer.trim().length > 0;
        html += '<button id="qbtn-' + i + '" style="font-size:11px;padding:4px 12px;border-radius:20px;border:0.5px solid var(--put);background:transparent;color:var(--put);cursor:pointer">' + (hasAnswer ? 'Reveal answer' : 'No answer available') + '</button>';
        html += '<div id="qans-' + i + '" style="display:none;margin-top:.5rem;font-size:12px;color:var(--put);line-height:1.45"><strong>' + esc(q.answer || 'No answer provided for this layer yet.') + '</strong>';
        if (q.why) html += '<div style="font-size:11px;opacity:.8;margin-top:3px">' + esc(q.why) + '</div>';
        html += '</div></div>';
      });
      html += '</div></div>';
    }
  }

  document.getElementById('layer-content').innerHTML = html;

  // Wire quiz buttons
  var quiz = (currentLayers[activeLayer] && currentLayers[activeLayer].quiz) || [];
  quiz.forEach(function(q, i) {
    var btn = document.getElementById('qbtn-' + i);
    if (btn) btn.addEventListener('click', function() {
      var ans = document.getElementById('qans-' + i);
      if (ans) ans.style.display = ans.style.display === 'block' ? 'none' : 'block';
    });
  });

  // Wire quiz toggle
  var qt = document.getElementById('quiz-toggle');
  var qc = document.getElementById('quiz-content');
  if (qt && qc) {
    qt.addEventListener('click', function() {
      var open = qc.style.display === 'block';
      qc.style.display = open ? 'none' : 'block';
      qt.style.background = open ? 'transparent' : 'var(--pul)';
    });
  }
}

async function runPart2() {
  document.getElementById('p2-banner').style.display = 'none';
  document.getElementById('p2-loading').style.display = 'block';

  try {
    var h = currentReport ? (currentReport.health||{}) : {};
    // Don't run Part 2 if app is already production ready
    if (h.score === 'A' && h.critical === 0) {
      document.getElementById('p2-loading').style.display = 'none';
      document.getElementById('p2-results').innerHTML = `
        <div style="background:var(--grl);border:0.5px solid var(--grt);border-radius:var(--r);padding:1.25rem 1.5rem;margin-bottom:1rem">
          <div style="font-size:18px;font-weight:700;color:var(--grt);margin-bottom:.5rem">🎉 Score A — Production Ready!</div>
          <div style="font-size:13px;color:var(--grt);line-height:1.6">Your app passed all critical checks. This is the best possible result — it means no major security holes were found and your app appears safe to share with real users.</div>
        </div>
        <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1.25rem 1.5rem;margin-bottom:1rem">
          <div style="font-size:13px;font-weight:600;margin-bottom:.75rem">💡 What Score A actually means</div>
          <div style="font-size:13px;color:var(--mut);line-height:1.7">
            Think of it like a building inspection. Score A means the inspector found no structural problems, the electrics are safe, and it's ready for people to move in.<br><br>
            It does <strong>not</strong> mean the app is perfect — just that the most important safety checks passed. Like a new car passing its roadworthy test — it's safe to drive, but you still need to maintain it over time.
          </div>
        </div>
        <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1.25rem 1.5rem;margin-bottom:1rem">
          <div style="font-size:13px;font-weight:600;margin-bottom:.75rem">🔍 What Verilay checked to give this score</div>
          <ul style="font-size:13px;color:var(--mut);line-height:1.9;padding-left:1.25rem">
            <li><strong>Auth layer</strong> — are logins and sessions properly secured?</li>
            <li><strong>Config layer</strong> — are secrets and API keys properly hidden?</li>
            <li><strong>Database layer</strong> — is user data protected with proper access rules?</li>
            <li><strong>API layer</strong> — are your endpoints protected from abuse?</li>
            <li><strong>Frontend layer</strong> — is sensitive data hidden from the browser?</li>
            <li><strong>Libraries layer</strong> — are your dependencies safe and up to date?</li>
          </ul>
        </div>
        <div style="background:var(--pul);border:0.5px solid var(--pu);border-radius:var(--r);padding:1.25rem 1.5rem;margin-bottom:1rem">
          <div style="font-size:13px;font-weight:600;color:var(--put);margin-bottom:.75rem">📚 Keep learning — what to do next</div>
          <div style="font-size:13px;color:var(--put);line-height:1.7">
            Your app scored A today but apps change as you add features. Good habits to build:<br><br>
            <strong>Re-run Verilay</strong> every time you add a new login method, payment system, or database table.<br>
            <strong>Check your Supabase dashboard</strong> regularly — make sure Row Level Security is on for every new table you create.<br>
            <strong>Never commit .env files</strong> to GitHub — your API keys should only live in your hosting platform's environment variables.
          </div>
        </div>
        <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1.25rem 1.5rem">
          <div style="font-size:13px;font-weight:600;margin-bottom:.75rem">🚀 Ready to go live?</div>
          <div style="font-size:13px;color:var(--mut);line-height:1.7">
            For apps handling real users and payments, we still recommend:<br><br>
            • <a href="https://snyk.io" target="_blank" style="color:var(--pu)">Snyk</a> — free dependency vulnerability scanner<br>
            • <a href="https://coderabbit.ai" target="_blank" style="color:var(--pu)">CodeRabbit</a> — AI code review on every update<br>
            • Test with real users before launching publicly — their behaviour will surface things no tool can predict
          </div>
        </div>`;
      return;
    }
    var findings = 'Score: '+h.score+', Critical: '+h.critical+', Warnings: '+h.warnings+'. ';
    findings += 'Stack: '+(currentReport?(currentReport.stack||[]).slice(0,5).map(function(s){return s.name;}).join(', '):'') + '. ';
    findings += 'Layers: '+Object.keys(currentLayers).map(function(n){return n+'('+currentLayers[n].status+')';}).join(', ');
    var resp = await fetch('/analyse-step4', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        repo_name:  currentReport ? currentReport.repo : '',
        built_with: currentReport ? (currentReport.built_with||'') : '',
        findings_summary: findings,
        report_id: savedReportId || ''
      })
    });
    var data = await resp.json();
    document.getElementById('p2-loading').style.display = 'none';
    if (data.error) {
      document.getElementById('p2-results').innerHTML = '<div style="background:var(--rdl);border-radius:8px;padding:.85rem;color:var(--rdt);font-size:12px;margin-top:.75rem">' + esc(data.error) + '</div>';
      return;
    }
    window._step4Data = data;
    renderPart2(data);
  } catch(e) {
    document.getElementById('p2-loading').style.display = 'none';
    document.getElementById('p2-results').innerHTML = '<div style="background:var(--rdl);border-radius:8px;padding:.85rem;color:var(--rdt);font-size:12px;margin-top:.75rem">Deep analysis timed out or failed — this can happen with large or complex apps. <a href=\'#\' onclick=\'runPart2();return false;\' style=\'color:var(--rd);font-weight:600\'>Try again</a> or skip and use the advice prompts above.</div>';
  }
}

function showLayerError(msg) {
  var loadingEl = document.getElementById('layers-loading');
  if (loadingEl) {
    loadingEl.innerHTML = '<i class="ti ti-alert-triangle" style="font-size:13px;color:var(--ort);flex-shrink:0"></i><span style="font-size:11px;color:var(--ort)">' + msg + '</span>';
    loadingEl.style.display = 'flex';
  }
}

function appendLayers(newLayers) {
  var nav = document.getElementById('layer-nav');
  if (!nav) return;

  var icons = {Auth:'ti-shield',Database:'ti-database',Config:'ti-lock',Frontend:'ti-layout',Libraries:'ti-package',API:'ti-api','File Handling':'ti-file'};
  var sdot = {critical:'#E24B4A',warning:'#EF9F27',passing:'#639922'};
  var sibg = {critical:'var(--rdl)',warning:'var(--orl)',passing:'var(--grl)'};
  var siclr = {critical:'var(--rdt)',warning:'var(--ort)',passing:'var(--grt)'};

  // Hide the loading indicator once first layers arrive
  var loadingEl = document.getElementById('layers-loading');
  if (loadingEl) loadingEl.style.display = 'none';

  // Show mode toggle
  var mt = document.getElementById('mode-toggle');
  if (mt) mt.style.display = 'flex';

  newLayers.forEach(function(layer) {
    currentLayers[layer.name] = layer;

    var btn = document.createElement('button');
    btn.className = 'lb';
    btn.dataset.layer = layer.name;
    btn.innerHTML =
      '<div class="lico" style="background:' + (sibg[layer.status]||sibg.passing) + ';color:' + (siclr[layer.status]||siclr.passing) + '">' +
      '<i class="ti ' + (icons[layer.name]||'ti-code') + '"></i></div>' +
      '<span style="flex:1">' + esc(layer.name) + '</span>' +
      '<div class="ldot" style="background:' + (sdot[layer.status]||sdot.passing) + '"></div>';

    btn.addEventListener('click', function() {
      document.querySelectorAll('#layer-nav .lb').forEach(function(b) { b.classList.remove('act'); });
      btn.classList.add('act');
      activeLayer = layer.name;
      activeMode = document.querySelector('#mode-toggle .mb.on') ?
        document.querySelector('#mode-toggle .mb.on').dataset.mode : 'expert';
      renderLayer();
    });
    nav.appendChild(btn);
  });

  // Auto-select first layer button if none selected
  if (!activeLayer) {
    var firstBtn = document.querySelector('#layer-nav .lb');
    if (firstBtn) firstBtn.click();
  }
}

function renderPart2(data) {
  var html = '<div style="margin-top:1rem">';
  var sec = data.security_score || {};
  var checks = [
    ['env_secrets_exposed','No secrets exposed in .env file',true,
      'Your .env file contains passwords and API keys. If committed to GitHub anyone can steal them and access your database or rack up API bills.',
      'Green = no .env file found in repo. Red = .env file detected in public code. Surface scans cannot check this.'],
    ['auth_properly_configured','Auth properly configured',false,
      'Auth controls who can log in to your app. Misconfigured auth means strangers could access user accounts or bypass login entirely.',
      'Green = auth middleware detected and properly configured. Red = no auth layer found or session handling appears missing from the files analysed.'],
    ['rls_likely_configured','Row Level Security configured',false,
      'Row Level Security (RLS) in Supabase controls which users can see which data. Without it, any logged-in user could read all other users data.',
      'Green = RLS policies detected in your code. Red = no RLS policies found in the files analysed — check your Supabase dashboard to confirm RLS is enabled on all tables.'],
    ['dependencies_current','Dependencies are current',false,
      'Outdated libraries often contain known security vulnerabilities that hackers can exploit. Keeping them updated is basic security hygiene.',
      'Green = package versions appear recent. Red = outdated or vulnerable packages detected. Surface scans cannot check package versions — use GitHub scan.'],
    ['no_hardcoded_secrets','No hardcoded secrets in code',false,
      'Hardcoded secrets (like API keys written directly in code) are visible to anyone who views your source. They should always be in environment variables instead.',
      'Green = no hardcoded keys found in visible code. Red = potential secrets detected in source. Surface scans can only check client-side code.']
  ];
  html += '<div style="font-size:10px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin-bottom:.5rem">Security checklist</div>';
  checks.forEach(function(c) {
    var v = sec[c[0]]; var inv = c[2];
    var pass = (v===null||v===undefined) ? null : (inv ? !v : v);
    var bg, clr, ico;
    if (pass===true) { bg='var(--grl)';clr='var(--grt)';ico='ti-circle-check'; }
    else if (pass===false) { bg='var(--rdl)';clr='var(--rdt)';ico='ti-alert-circle'; }
    else { bg='#F1EFE8';clr='#5F5E5A';ico='ti-minus'; }
    var checkId = 'check-' + c[0];
    html += '<div class="si" style="background:' + bg + ';color:' + clr + ';cursor:pointer;flex-direction:column;align-items:flex-start" onclick="toggleCheck(\'' + checkId + '\')">';
    html += '<div style="display:flex;align-items:center;gap:8px;width:100%">';
    html += '<i class="ti ' + ico + '" style="font-size:15px;flex-shrink:0"></i>';
    html += '<span style="flex:1;font-weight:500">' + c[1] + '</span>';
    html += '<i class="ti ti-chevron-down" style="font-size:12px;opacity:.6" id="' + checkId + '-ico"></i>';
    html += '</div>';
    html += '<div id="' + checkId + '" style="display:none;margin-top:.6rem;padding-top:.6rem;border-top:0.5px solid currentColor;opacity:.8;width:100%">';
    html += '<div style="font-size:11px;font-weight:600;margin-bottom:.3rem">Why it matters:</div>';
    html += '<div style="font-size:11px;line-height:1.55;margin-bottom:.5rem">' + esc(c[3]||'') + '</div>';
    html += '<div style="font-size:11px;font-weight:600;margin-bottom:.3rem">What this result means:</div>';
    html += '<div style="font-size:11px;line-height:1.55">' + esc(c[4]||'') + '</div>';
    html += '</div>';
    html += '</div>';
  });
  html += '<div style="font-size:10px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin:.85rem 0 .5rem">Fix list</div>';
  var builtWith = (currentReport && currentReport.built_with) ? currentReport.built_with.toLowerCase() : '';
  var isLovable = builtWith.includes('lovable');
  var isReplit  = builtWith.includes('replit');
  var isBolt    = builtWith.includes('bolt');
  var isV0      = builtWith.includes('v0');

  (data.top_fixes||[]).forEach(function(f, fi) {
    // Choose the right platform prompt
    var platformPrompt = f.general_prompt || f.lovable_prompt || '';
    var platformLabel = 'Get advice prompt';
    var platformIcon = 'ti-bulb';
    if (isLovable && f.lovable_prompt) {
      platformPrompt = f.lovable_prompt;
      platformLabel = 'Ask Lovable about this';
      platformIcon = 'ti-bulb';
    } else if (isReplit && f.replit_prompt) {
      platformPrompt = f.replit_prompt;
      platformLabel = 'Ask Replit about this';
      platformIcon = 'ti-bulb';
    } else if (isBolt && f.general_prompt) {
      platformLabel = 'Fix in Bolt';
      platformIcon = 'ti-bolt';
    } else if (isV0 && f.general_prompt) {
      platformLabel = 'Fix in v0';
      platformIcon = 'ti-code';
    }

    html += '<div class="fc"><div style="display:flex;gap:12px;align-items:flex-start">';
    html += '<div style="width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;flex-shrink:0;background:var(--pul);color:var(--put)">' + (f.priority||'') + '</div>';
    html += '<div style="flex:1">';
    html += '<div style="font-size:13px;font-weight:500;margin-bottom:3px">' + esc(f.title||'') + '</div>';
    html += '<div style="font-size:12px;color:var(--mut);margin-bottom:4px;line-height:1.4">' + esc(f.why_it_matters||'') + '</div>';
    html += '<div style="font-size:11px;background:var(--bg);border-radius:6px;padding:5px 8px;color:var(--mut);line-height:1.5;margin-bottom:.5rem">' + esc(f.how_to_fix||'') + '</div>';
    html += '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">';
    html += '<span style="font-size:10px;font-weight:500;padding:2px 8px;border-radius:20px;background:var(--pul);color:var(--put)">' + esc(f.estimated_effort||'varies') + '</span>';
    if (platformPrompt) {
      html += '<button id="fix-btn-' + fi + '" style="display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:500;padding:4px 12px;border-radius:20px;background:var(--pu);color:#fff;border:none;cursor:pointer">';
      html += '<i class="ti ' + platformIcon + '" style="font-size:12px"></i> ' + platformLabel;
      html += '</button>';
      html += '<span id="fix-copied-' + fi + '" style="font-size:11px;color:var(--grt);display:none">✓ Copied! Paste into your AI chat</span>';
    }
    html += '</div>';
    if (platformPrompt) {
      html += '<div style="margin-top:.5rem;background:var(--bg);border-radius:6px;padding:.5rem .75rem;font-size:11px;font-family:monospace;color:var(--mut);white-space:pre-wrap;word-break:break-all;max-height:80px;overflow:hidden;line-height:1.5" id="fix-prompt-' + fi + '">' + esc(platformPrompt) + '</div>';
    }
    html += '</div></div></div>';
  });

  // Wire fix buttons after render
  setTimeout(function() {
    (data.top_fixes||[]).forEach(function(f, fi) {
      var btn = document.getElementById('fix-btn-' + fi);
      var copied = document.getElementById('fix-copied-' + fi);
      var prompt = f.general_prompt || f.lovable_prompt || '';
      if (isLovable && f.lovable_prompt) prompt = f.lovable_prompt;
      else if (isReplit && f.replit_prompt) prompt = f.replit_prompt;
      if (btn && prompt) {
        btn.addEventListener('click', function() {
          // Show safety reminder before copying
          var confirmed = confirm(
            'Before applying this advice:\n\n' +
            '1. Paste it into Lovable or Replit\n' +
            '2. Read their response carefully\n' +
            '3. Ask them to ADVISE first — not make changes yet\n' +
            '4. Only apply changes they confirm are safe\n\n' +
            'Copy advice prompt?'
          );
          if (!confirmed) return;
          navigator.clipboard.writeText(prompt).then(function() {
            btn.style.background = 'var(--gr)';
            if (copied) { copied.style.display = 'inline'; }
            setTimeout(function() {
              btn.style.background = 'var(--pu)';
              if (copied) { copied.style.display = 'none'; }
            }, 3000);
          });
        });
      }
    });
  }, 100);
  var so = data.second_opinion || {};
  var soItems = [
    ['General second opinion', so.summary_prompt, 'ti-message-dots'],
    ['Security verification', so.security_prompt, 'ti-shield-check'],
    ['Production readiness', so.prod_checklist_prompt, 'ti-rocket']
  ];
  // Next steps recommendation
  html += '<div style="background:var(--pul);border-radius:var(--r);padding:.85rem 1rem;margin:.85rem 0;border-left:3px solid var(--pu)">';
  html += '<div style="font-size:12px;font-weight:600;color:var(--put);margin-bottom:.4rem"><i class="ti ti-arrow-right" style="margin-right:4px"></i>Recommended next steps</div>';
  html += '<div style="font-size:12px;color:var(--put);line-height:1.6">';
  html += 'Verilay gives you a first-pass overview - good for understanding and catching obvious issues. For production apps we recommend going further:<br>';
  html += '• <a href="https://snyk.io" target="_blank" style="color:var(--pu)">Snyk</a> - free dependency and vulnerability scanning (connects to GitHub)<br>';
  html += '• <a href="https://coderabbit.ai" target="_blank" style="color:var(--pu)">CodeRabbit</a> - AI code review on every pull request (free for open source)<br>';
  html += '• Share the second opinion prompts below with a developer for a human review<br>';
  html += '• Fix all critical issues before going live with real users or payments';
  html += '</div></div>';

  html += '<div style="font-size:10px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin:.85rem 0 .5rem">Second opinion - verify with any AI</div>';
  html += '<div style="font-size:12px;color:var(--mut);margin-bottom:.75rem">Copy any prompt into Claude or ChatGPT to independently verify findings.</div>';
  soItems.forEach(function(item) {
    if (!item[1]) return;
    html += '<div class="so-card"><div style="font-size:12px;font-weight:500;margin-bottom:.4rem;display:flex;align-items:center;gap:6px"><i class="ti ' + item[2] + '" style="font-size:14px;color:var(--pu)"></i>' + item[0] + '</div>';
    html += '<div style="background:var(--bg);border-radius:6px;padding:.6rem .75rem;font-size:11px;font-family:monospace;color:var(--mut);white-space:pre-wrap;word-break:break-all;max-height:150px;overflow-y:auto;line-height:1.5">' + esc(item[1]) + '</div>';
    html += '<div style="display:flex;gap:6px;margin-top:.5rem">';
    html += '<a href="https://claude.ai" target="_blank" style="font-size:11px;padding:4px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--txt);text-decoration:none">Open Claude</a>';
    html += '<a href="https://chat.openai.com" target="_blank" style="font-size:11px;padding:4px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--txt);text-decoration:none">Open ChatGPT</a>';
    html += '</div></div>';
  });
  html += '</div>';
  document.getElementById('p2-results').innerHTML = html;
}

// Start everything when DOM is ready
// Verifications store
var currentVerifications = {};

function showVerifyPanel(findingKey, btn) {
  var panel = document.getElementById('verify-panel-' + findingKey);
  if (!panel) return;
  var isOpen = panel.style.display === 'block';
  panel.style.display = isOpen ? 'none' : 'block';
  btn.textContent = isOpen ? '✓ Mark as verified' : '✕ Cancel';
}

async function submitVerification(findingKey, verdict) {
  var textarea = document.getElementById('verify-text-' + findingKey);
  var builderResponse = textarea ? textarea.value.trim() : '';

  // Require builder response before submitting
  if (!builderResponse || builderResponse.length < 10) {
    if (textarea) {
      textarea.style.border = '1.5px solid #E24B4A';
      textarea.placeholder = 'Please paste your AI builder response first before verifying...';
      textarea.focus();
    }
    return;
  }

  if (!savedReportId) {
    alert('Please wait for the report to save before verifying findings.');
    return;
  }

  try {
    var resp = await fetch('/verify-finding', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        report_id: savedReportId,
        finding_key: findingKey,
        builder_response: builderResponse,
        verdict: verdict
      })
    });
    var data = await resp.json();
    if (data.ok) {
      currentVerifications = data.verifications || currentVerifications;
      currentVerifications[findingKey] = {
        verdict: verdict,
        builder_response: builderResponse
      };
      // Don't re-render full report - just update this finding panel
      var panel = document.getElementById('verify-panel-' + findingKey);
      var btn = panel ? panel.previousElementSibling : null;
      if (panel) {
        panel.style.display = 'none';
        // Show verified state inline
        var verifiedDiv = document.createElement('div');
        verifiedDiv.style.cssText = 'margin-top:8px;padding:6px 10px;background:#F0FDF4;border:0.5px solid #22C55E;border-radius:6px;font-size:11px;color:#166534';
        verifiedDiv.innerHTML = '<strong>✅ Verified by AI builder</strong>' +
          (verdict === 'false_positive' ? ' — confirmed not an issue' : verdict === 'fixed' ? ' — confirmed fixed' : ' — verified real issue') +
          (builderResponse ? '<div style="margin-top:3px;opacity:.8;font-size:10px">' + builderResponse.substring(0,120) + (builderResponse.length > 120 ? '...' : '') + '</div>' : '');
        if (panel.parentNode) panel.parentNode.replaceChild(verifiedDiv, panel);
        if (btn) btn.style.display = 'none';
      }
      // Recalculate score and update layer dot directly
      updateVerifiedScore();
      // Also directly update the layer dot for the current active layer
      if (activeLayer) {
        var layerFindings = (currentLayers[activeLayer] && currentLayers[activeLayer].expert || {}).findings || [];
        var hasUnverified = layerFindings.some(function(f, fi) {
          var k = (activeLayer + '_' + fi).replace(/[^a-z0-9]/gi, '_').toLowerCase();
          return !currentVerifications[k] && (f.severity === 'critical' || f.severity === 'warning');
        });
        if (!hasUnverified && layerFindings.length > 0) {
          updateLayerDot(activeLayer, true);
        }
      }
    }
  } catch(e) {
    console.error('Verify error:', e);
  }
}

function updateVerifiedScore() {
  // Use currentLayers which is where layer data actually lives
  var layerNames = Object.keys(currentLayers);
  if (layerNames.length === 0) return;
  var unverifiedCritical = 0;
  var unverifiedWarnings = 0;
  var verifiedCount = 0;
  var fixedCount = 0;
  var falsePositiveCount = 0;

  layerNames.forEach(function(layerName) {
    var layer = currentLayers[layerName];
    layer.name = layerName;  // ensure name is set
    var findings = (layer.expert || {}).findings || [];
    var layerUnverified = 0;
    findings.forEach(function(f, fi) {
      var key = (layerName + '_' + fi).replace(/[^a-z0-9]/gi, '_').toLowerCase();
      var v = currentVerifications[key];
      if (v) {
        verifiedCount++;
        if (v.verdict === 'fixed') fixedCount++;
        if (v.verdict === 'false_positive') falsePositiveCount++;
      } else {
        if (f.severity === 'critical') { unverifiedCritical++; layerUnverified++; }
        if (f.severity === 'warning') { unverifiedWarnings++; layerUnverified++; }
      }
    });

    // Update layer dot colour if all findings verified
    if (findings.length > 0 && layerUnverified === 0) {
      // Find the layer button and update its dot
      var layerBtns = document.querySelectorAll('.layer-btn, [data-layer]');
      layerBtns.forEach(function(btn) {
        if (btn.textContent.trim().indexOf(layer.name) > -1) {
          var dot = btn.querySelector('.dot, i[style*="border-radius"]');
          if (dot) {
            dot.style.background = 'var(--gr)';
            dot.style.color = 'var(--grt)';
          }
        }
      });
      // Also update via layer name in the sidebar
      updateLayerDot(layerName, true);
    }
  });

  // Recalculate score based on unverified findings only
  var newScore;
  if (unverifiedCritical === 0 && unverifiedWarnings === 0) {
    newScore = 'A';
  } else if (unverifiedCritical === 0 && unverifiedWarnings <= 3) {
    newScore = 'B';
  } else if (unverifiedCritical <= 1 && unverifiedWarnings <= 5) {
    newScore = 'C';
  } else if (unverifiedCritical <= 3) {
    newScore = 'D';
  } else {
    newScore = 'F';
  }

  // Update score display if improved
  var originalScore = (currentReport && currentReport.health) ? currentReport.health.score : null;
  var scoreColors = {A:'#1D9E75',B:'#4A90D9',C:'#EF9F27',D:'#E24B4A',F:'#A32D2D'};
  var scores = ['F','D','C','B','A'];

  if (verifiedCount > 0) {
    // Update score box
    var scoreBoxes = document.querySelectorAll('.hc');
    scoreBoxes.forEach(function(box) {
      if (box.textContent.trim().includes('score') || box.querySelector('div') && ['A','B','C','D','F'].includes(box.querySelector('div').textContent.trim())) {
        var scoreDiv = box.querySelector('div');
        if (scoreDiv && ['A','B','C','D','F'].includes(scoreDiv.textContent.trim())) {
          scoreDiv.textContent = newScore;
          scoreDiv.style.color = scoreColors[newScore] || '#999';
          box.style.background = newScore === 'A' ? 'var(--grl)' : newScore === 'B' ? '#EFF6FF' : newScore === 'C' ? '#FEF9C3' : 'var(--rdl)';
        }
      }
    });

    // Show verified summary banner
    var existing = document.getElementById('verified-summary');
    if (!existing) {
      var banner = document.createElement('div');
      banner.id = 'verified-summary';
      var reportEl = document.getElementById('report');
      if (reportEl) reportEl.insertBefore(banner, reportEl.firstChild);
      existing = banner;
    }
    existing.style.cssText = 'background:#F0FDF4;border:0.5px solid #22C55E;border-radius:8px;padding:.85rem 1rem;margin-bottom:10px;font-size:12px;color:#166534;line-height:1.6';

    var improved = scores.indexOf(newScore) > scores.indexOf(originalScore);
    var scoreLine = improved
      ? '▲ Score updated: <strong>' + originalScore + ' → ' + newScore + '</strong> after verifying findings with your AI builder'
      : 'Score: <strong>' + newScore + '</strong> (based on unverified findings)';

    existing.innerHTML =
      '✅ <strong>' + verifiedCount + ' finding' + (verifiedCount > 1 ? 's' : '') + ' verified</strong> — ' + scoreLine + '<br>' +
      (fixedCount > 0 ? fixedCount + ' fixed · ' : '') +
      (falsePositiveCount > 0 ? falsePositiveCount + ' false positive' + (falsePositiveCount > 1 ? 's' : '') + ' · ' : '') +
      (unverifiedCritical > 0 ? '<span style="color:#E24B4A">' + unverifiedCritical + ' critical still need attention</span>' : 'all critical issues accounted for');
  }
}

// Waitlist nudge
function showWaitlistNudge(count) {
  var existing = document.getElementById('waitlist-nudge');
  if (existing) return;

  var nudge = document.createElement('div');
  nudge.id = 'waitlist-nudge';
  nudge.style.cssText = 'position:fixed;bottom:20px;right:20px;width:320px;background:var(--sur);border:0.5px solid var(--pu);border-radius:12px;padding:1.1rem 1.25rem;box-shadow:0 4px 20px rgba(0,0,0,.12);z-index:9999;font-size:13px';
  nudge.innerHTML =
    '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:.5rem">' +
    '<div style="font-weight:600;color:var(--txt)">Enjoying Verilay? 🎉</div>' +
    '<button onclick="dismissWaitlist()" style="background:none;border:none;cursor:pointer;color:var(--mut);font-size:16px;padding:0;line-height:1">×</button>' +
    '</div>' +
    '<div style="color:var(--mut);margin-bottom:.75rem;line-height:1.5">You\'ve run ' + count + ' analyses. We\'re building <strong>persistent history</strong>, <strong>email reports</strong>, and <strong>saved verifications</strong> so your progress carries forward.</div>' +
    '<div style="color:var(--mut);font-size:11px;margin-bottom:.65rem">Join the waitlist — free, no commitment.</div>' +
    '<div style="display:flex;gap:6px">' +
    '<input id="waitlist-email" type="email" placeholder="your@email.com" style="flex:1;font-size:12px;padding:6px 10px;border:0.5px solid var(--bdr);border-radius:6px;background:var(--bg);color:var(--txt)">' +
    '<button onclick="submitWaitlist()" style="font-size:12px;padding:6px 14px;border-radius:6px;background:var(--pu);color:#fff;border:none;cursor:pointer;white-space:nowrap">Join →</button>' +
    '</div>' +
    '<div id="waitlist-msg" style="font-size:11px;margin-top:6px;color:var(--gr);display:none"></div>';

  document.body.appendChild(nudge);
}

async function submitWaitlist() {
  var email = document.getElementById('waitlist-email');
  var msg = document.getElementById('waitlist-msg');
  if (!email || !email.value.trim() || email.value.indexOf('@') === -1) {
    if (email) email.style.border = '1.5px solid #E24B4A';
    return;
  }

  try {
    var resp = await fetch('/waitlist', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        email: email.value.trim(),
        analyses_count: parseInt(localStorage.getItem('verilay_analysis_count') || '0'),
        source: 'nudge_banner'
      })
    });
    var data = await resp.json();
    if (data.ok) {
      localStorage.setItem('verilay_waitlist_shown', '1');
      if (msg) {
        msg.style.display = 'block';
        msg.textContent = data.already ? 'Already on the list — we\'ll be in touch!' : '✅ You\'re on the list! We\'ll email you when it\'s ready.';
      }
      setTimeout(function() { dismissWaitlist(); }, 3000);
    }
  } catch(e) {
    console.error('Waitlist error:', e);
  }
}

function dismissWaitlist() {
  var nudge = document.getElementById('waitlist-nudge');
  if (nudge) nudge.remove();
  localStorage.setItem('verilay_waitlist_shown', '1');
}

// Delete report
async function deleteReport() {
  if (!savedReportId) return;
  if (!confirm('Delete this report? The findings will be removed. This cannot be undone.')) return;
  try {
    var resp = await fetch('/delete-report/' + savedReportId, { method: 'POST' });
    var data = await resp.json();
    if (data.ok) {
      // Clear the report from view
      document.getElementById('report').innerHTML = '<div style="text-align:center;padding:2rem;color:var(--mut)">Report deleted.</div>';
      savedReportId = null;
      // Remove from local history
      var history = getHistory();
      var filtered = history.filter(function(h) { return h.id !== savedReportId; });
      localStorage.setItem('verilay_history', JSON.stringify(filtered));
    }
  } catch(e) {
    console.error('Delete error:', e);
  }
}

// Toggle accuracy tip
function toggleAccuracyTip() {
  var el = document.getElementById('accuracy-tip');
  var ico = document.getElementById('accuracy-tip-ico');
  if (!el) return;
  var open = el.style.display === 'block';
  el.style.display = open ? 'none' : 'block';
  if (ico) ico.style.transform = open ? '' : 'rotate(180deg)';
}

function copyAccuracyPrompt() {
  var text = 'Add a JSDoc comment block to the top of each edge/serverless function with these fields: @auth-required: true|false, @auth-method: in-code|gateway|none, @public: true|false (and reason if true e.g. "inbound webhook" or "landing page demo"). Also create a SECURITY.md explaining your project auth model. This helps security scanners understand your app correctly.';
  navigator.clipboard.writeText(text).then(function() {
    var btn = document.getElementById('copy-accuracy-btn');
    if (btn) { btn.textContent = 'Copied!'; setTimeout(function() { btn.textContent = 'Copy'; }, 2000); }
  }).catch(function() {
    var btn = document.getElementById('copy-accuracy-btn');
    if (btn) btn.textContent = 'Copy';
  });
}

// Toggle older history items
function toggleOlderHistory() {
  var items = document.querySelectorAll('.history-item');
  var btn = document.getElementById('btn-show-more');
  var showing = btn && btn.textContent.indexOf('Hide') > -1;
  items.forEach(function(item, i) {
    if (i >= 2) item.style.display = showing ? 'none' : 'flex';
  });
  if (btn) btn.textContent = showing ? 'Show older analyses ▾' : 'Hide older analyses ▴';
}

// Update layer dot to green when all findings verified
function updateLayerDot(layerName, allVerified) {
  // Find layer button by data-layer attribute
  var btn = document.querySelector('#layer-nav .lb[data-layer="' + layerName + '"]');
  if (!btn) return;

  if (allVerified) {
    // Update the dot to green
    var dot = btn.querySelector('.ldot');
    if (dot) {
      dot.style.background = '#1D9E75';
      dot.title = '✅ All findings verified';
    }
    // Update the icon background to green
    var ico = btn.querySelector('.lico');
    if (ico) {
      ico.style.background = 'var(--grl)';
      ico.style.color = 'var(--grt)';
    }
    // Add verified badge next to layer name
    var span = btn.querySelector('span');
    if (span && span.textContent.indexOf('✅') === -1) {
      span.innerHTML = esc(layerName) + ' <span style="font-size:9px;background:#1D9E75;color:#fff;border-radius:8px;padding:1px 5px;margin-left:4px">verified</span>';
    }
  }
}

// Toggle security checklist item
function toggleCheck(id) {
  var el = document.getElementById(id);
  var ico = document.getElementById(id + '-ico');
  if (!el) return;
  var open = el.style.display === 'block';
  el.style.display = open ? 'none' : 'block';
  if (ico) ico.style.transform = open ? '' : 'rotate(180deg)';
}

// Feedback functions
function submitFeedback(helpful) {
  var upBtn = document.getElementById('btn-feedback-up');
  var downBtn = document.getElementById('btn-feedback-down');
  if (upBtn) upBtn.style.background = helpful ? '#EAF3DE' : 'none';
  if (downBtn) downBtn.style.background = !helpful ? '#FCEBEB' : 'none';
  if (!helpful) {
    var ta = document.getElementById('feedback-text-area');
    if (ta) ta.style.display = 'block';
  } else {
    sendFeedback(true, '');
  }
}

function sendFeedbackText() {
  var text = document.getElementById('feedback-text');
  sendFeedback(false, text ? text.value : '');
}

function sendFeedback(helpful, comment) {
  fetch('/feedback', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      helpful: helpful,
      comment: comment,
      report_id: savedReportId || ''
    })
  }).catch(function() {});
  var ta = document.getElementById('feedback-text-area');
  if (ta) ta.style.display = 'none';
  var thanks = document.getElementById('feedback-thanks');
  if (thanks) thanks.style.display = 'block';
  var btns = document.getElementById('btn-feedback-up');
  if (btns) btns.parentElement.style.display = 'none';
}

// Ask AI about report
function askAIAboutReport() {
  if (!currentReport) return;
  var h = currentReport.health || {};
  var layers = currentReport.layers || [];
  var findings = layers.map(function(l) {
    var ex = l.expert || {};
    var issues = (ex.findings || []).filter(function(f) {
      return f.severity === 'critical' || f.severity === 'warning';
    }).map(function(f) {
      return f.severity.toUpperCase() + ': ' + f.title + ' — ' + f.detail;
    }).join('\n');
    return issues ? l.name + ' layer:\n' + issues : null;
  }).filter(Boolean).join('\n\n');

  var prompt = 'I ran Verilay on my app (' + (currentReport.repo || 'my app') + ') and got these findings:\n\n' +
    'Score: ' + (h.score || '?') + '\n' +
    'Built with: ' + (currentReport.built_with || 'AI tools') + '\n\n' +
    (findings || 'No critical issues found.') + '\n\n' +
    'Can you explain these findings in simple terms and tell me how to fix the most important ones in ' +
    (currentReport.built_with && currentReport.built_with.toLowerCase().includes('lovable') ? 'Lovable' :
     currentReport.built_with && currentReport.built_with.toLowerCase().includes('replit') ? 'Replit' :
     'my AI builder') + '? I am not a developer so please keep it simple.';

  var url = 'https://claude.ai/new?q=' + encodeURIComponent(prompt);
  window.open(url, '_blank');
}

document.addEventListener('DOMContentLoaded', init);
