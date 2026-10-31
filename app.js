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

// Manage token: proves this browser created a report. The server sends it once, when the report is
// saved, and only a hash of it is kept there. It is needed to verify a finding, store the fix list or
// delete the report. Kept in localStorage (so it survives a reload) and in memory (if storage is blocked).
function storeReportToken(id, tok) {
  if (!id || !tok) return;
  window._reportTokens = window._reportTokens || {};
  window._reportTokens[id] = tok;
  try { localStorage.setItem('verilay_tok_' + id, tok); } catch (e) {}
}
function reportToken(id) {
  if (!id) return '';
  var m = (window._reportTokens || {})[id];
  if (m) return m;
  try { return localStorage.getItem('verilay_tok_' + id) || ''; } catch (e) { return ''; }
}
function reportHeaders(id, extra) {
  var h = Object.assign({}, extra || {});
  var tok = reportToken(id);
  if (tok) h['X-Report-Token'] = tok;
  return h;
}

async function autoSaveReport(data) {
  // Silently save in background and show share URL when ready
  try {
    var reportData = Object.assign({}, data);
    if ((window._incompleteLayers || []).length) {
      reportData.layers_not_checked = window._incompleteLayers.slice();
      if (scanFullyIncomplete()) reportData.analysis_incomplete = window._incompleteLayers.slice();
    }
    var resp = await fetch('/save-report', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(reportData)
    });
    var result = await resp.json();
    if (result.report_id) {
      savedReportId = result.report_id;
      storeReportToken(result.report_id, result.manage_token);
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
    if ((window._incompleteLayers || []).length) {
      reportData.layers_not_checked = window._incompleteLayers.slice();
      if (scanFullyIncomplete()) reportData.analysis_incomplete = window._incompleteLayers.slice();
    }
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
      storeReportToken(data.report_id, data.manage_token);
      var shareUrl = window.location.origin + '/report/' + data.report_id;
      document.getElementById('share-url').value = shareUrl;
      document.getElementById('share-banner').style.display = 'flex';
      btn.innerHTML = '<i class="ti ti-check" style="font-size:13px"></i> Saved';
      btn.style.color = 'var(--grt)';
    }
  } catch(e) {
    btn.textContent = 'Save failed';
    btn.disabled = false;
  }
}

// ── App directory: "List my app" after a free scan ───────────────────────────
// Uses the report id the SERVER saved for this scan (kept in the card), not savedReportId: the
// Share link button saves a fresh browser copy, and a browser-saved copy cannot be listed.
var DIR_BUILT_WITH = ['Lovable', 'Bolt', 'Replit', 'Base44', 'v0', 'Cursor', 'Windsurf', 'Claude Code', 'GitHub Copilot', 'Other AI tool'];
var DIR_CATEGORIES = [['business', 'Business & productivity'], ['money', 'Money & finance'], ['home', 'Home & property'],
  ['health', 'Health & fitness'], ['education', 'Education & careers'], ['marketing', 'Marketing & sales'],
  ['community', 'Community & social'], ['ai', 'AI tools'], ['developer', 'Developer tools'], ['other', 'Something else']];

function showDirectoryCard(reportId) {
  if (!reportId) return;
  var old = document.getElementById('directory-card');
  if (old) old.remove();
  var banner = document.getElementById('share-banner');
  if (!banner || !banner.parentNode) return;
  var card = document.createElement('div');
  card.id = 'directory-card';
  card.setAttribute('data-report', reportId);
  card.style.cssText = 'background:var(--pul);border:0.5px solid var(--pu);border-radius:var(--r);padding:.85rem 1rem;margin-bottom:.75rem';
  var field = 'width:100%;border:0.5px solid var(--bdr);border-radius:6px;padding:7px 9px;font-size:13px;font-family:inherit;background:white;color:var(--txt);margin-top:3px';
  var lab = 'display:block;font-size:12px;font-weight:600;color:var(--put);margin-top:.6rem';
  card.innerHTML =
    '<div style="display:flex;align-items:flex-start;gap:10px">' +
      '<i class="ti ti-building-store" style="font-size:20px;color:var(--pu);flex-shrink:0;margin-top:1px"></i>' +
      '<div style="flex:1;min-width:0">' +
        '<div style="font-size:14px;font-weight:600;color:var(--put)">List your app in the Verilay app directory, free</div>' +
        '<div style="font-size:12px;color:var(--put);line-height:1.55;margin-top:2px">A searchable home for apps built with AI tools, ' +
          'so people can find yours and get in touch. If this scan found no critical issues, your listing carries the ' +
          '<strong>Checked by Verilay</strong> stamp. Your findings stay private: only what you type below is shown. ' +
          '<a href="/apps" target="_blank" style="color:var(--put)">See the directory</a></div>' +
        '<button type="button" id="dir-open" class="btn-sm" style="margin-top:.6rem">List my app</button>' +
        '<form id="dir-form" style="display:none" novalidate>' +
          '<label style="' + lab + '" for="dir-name">App name</label><input id="dir-name" maxlength="60" style="' + field + '">' +
          '<label style="' + lab + '" for="dir-tagline">What does it do, in one line?</label>' +
            '<input id="dir-tagline" maxlength="140" placeholder="e.g. Tracks every stage of your new home build" style="' + field + '">' +
          '<label style="' + lab + '" for="dir-url">Where can people use it? (web address)</label>' +
            '<input id="dir-url" maxlength="200" placeholder="https://yourapp.com" autocapitalize="none" spellcheck="false" style="' + field + '">' +
          '<label style="' + lab + '" for="dir-built">Built with</label><select id="dir-built" style="' + field + '"></select>' +
          '<label style="' + lab + '" for="dir-cat">Category</label><select id="dir-cat" style="' + field + '"></select>' +
          '<label style="' + lab + '" for="dir-builder">Your name or business name (shown on your listing)</label>' +
            '<input id="dir-builder" maxlength="60" autocomplete="name" style="' + field + '">' +
          '<label style="' + lab + '" for="dir-contact">Your email (private: visitors\' messages are sent here, never shown)</label>' +
            '<input id="dir-contact" type="email" maxlength="254" autocomplete="email" autocapitalize="none" spellcheck="false" style="' + field + '">' +
          '<label style="display:flex;gap:6px;align-items:center;font-size:12px;color:var(--put);margin-top:.6rem"><input type="checkbox" id="dir-beta"> Looking for beta testers</label>' +
          '<label style="display:flex;gap:6px;align-items:center;font-size:12px;color:var(--put);margin-top:.3rem"><input type="checkbox" id="dir-custom"> Open to custom work</label>' +
          '<label style="display:flex;gap:6px;align-items:flex-start;font-size:12px;color:var(--put);margin-top:.6rem;line-height:1.5"><input type="checkbox" id="dir-confirm" style="margin-top:2px"> ' +
            'I built this app with AI tools and I am happy for these details to be listed publicly.</label>' +
          '<input type="text" id="dir-website" tabindex="-1" autocomplete="off" aria-hidden="true" style="position:absolute;left:-9999px">' +
          '<div id="dir-msg" style="display:none;font-size:12px;margin-top:.6rem;padding:7px 9px;border-radius:6px"></div>' +
          '<button type="submit" id="dir-submit" class="btn-sm" style="margin-top:.7rem">Submit listing</button>' +
          '<div style="font-size:11px;color:var(--put);opacity:.85;margin-top:.4rem">Listings are reviewed before they appear, usually within a day.</div>' +
        '</form>' +
      '</div>' +
    '</div>';
  banner.parentNode.insertBefore(card, banner.nextSibling);

  var built = card.querySelector('#dir-built');
  var detected = ((currentReport && currentReport.built_with) || '').toLowerCase();
  var guess = '';
  DIR_BUILT_WITH.forEach(function (b) { if (!guess && b !== 'Other AI tool' && detected.indexOf(b.toLowerCase()) > -1) guess = b; });
  built.innerHTML = '<option value="">Choose one</option>';
  DIR_BUILT_WITH.forEach(function (b) {
    var o = document.createElement('option'); o.value = b; o.textContent = b; if (b === guess) o.selected = true; built.appendChild(o);
  });
  var cat = card.querySelector('#dir-cat');
  cat.innerHTML = '<option value="">Choose one</option>';
  DIR_CATEGORIES.forEach(function (c) {
    var o = document.createElement('option'); o.value = c[0]; o.textContent = c[1]; cat.appendChild(o);
  });
  var repo = (currentReport && currentReport.repo) || '';
  var nameGuess = repo.split('/').pop().replace(/[-_]+/g, ' ').trim();
  card.querySelector('#dir-name').value = nameGuess ? nameGuess.charAt(0).toUpperCase() + nameGuess.slice(1) : '';

  card.querySelector('#dir-open').addEventListener('click', function () {
    this.style.display = 'none';
    card.querySelector('#dir-form').style.display = 'block';
    card.querySelector('#dir-tagline').focus();
    try { if (typeof plausible === 'function') plausible('Directory Form Open'); } catch (e) {}
  });
  card.querySelector('#dir-form').addEventListener('submit', submitDirectoryListing);
}

function _dirMsg(text, ok) {
  var m = document.getElementById('dir-msg');
  if (!m) return;
  m.textContent = text;
  m.style.display = 'block';
  m.style.background = ok ? 'var(--grl)' : '#FCEBEB';
  m.style.color = ok ? 'var(--grt)' : '#A32D2D';
}

async function submitDirectoryListing(e) {
  e.preventDefault();
  var card = document.getElementById('directory-card');
  if (!card) return;
  var reportId = card.getAttribute('data-report');
  var v = function (id) { var el = card.querySelector('#' + id); return el ? el.value.trim() : ''; };
  var c = function (id) { var el = card.querySelector('#' + id); return !!(el && el.checked); };
  if (!c('dir-confirm')) { _dirMsg('Please tick the box to confirm you built it with AI tools.', false); return; }
  var btn = card.querySelector('#dir-submit');
  btn.disabled = true;
  btn.textContent = 'Submitting...';
  try {
    var resp = await fetch('/apps/list', {
      method: 'POST',
      headers: reportHeaders(reportId, {'Content-Type': 'application/json'}),
      body: JSON.stringify({
        report_id: reportId, app_name: v('dir-name'), tagline: v('dir-tagline'), app_url: v('dir-url'),
        built_with: v('dir-built'), category: v('dir-cat'), builder_name: v('dir-builder'), contact: v('dir-contact'),
        beta_testers: c('dir-beta'), custom_work: c('dir-custom'), confirm: c('dir-confirm'), website: v('dir-website')
      })
    });
    var out = {};
    try { out = await resp.json(); } catch (e2) {}
    if (resp.ok && out.ok) {
      card.querySelector('#dir-form').querySelectorAll('input,select').forEach(function (el) { el.disabled = true; });
      btn.style.display = 'none';
      _dirMsg(out.stamped
        ? 'Thank you! Your app will appear on verilay.dev/apps with the Checked by Verilay stamp once it has been reviewed. ' +
          'We will email you when it is live, with a stamp you can put on your own site.'
        : 'Thank you! Your app will appear on verilay.dev/apps once it has been reviewed. This scan found issues to fix first, ' +
          'so it is listed without the stamp: fix them, scan again and list it again to earn the stamp.', true);
      try { if (typeof plausible === 'function') plausible('Directory Listing Submit', {props: {stamped: out.stamped ? 'yes' : 'no'}}); } catch (e3) {}
    } else {
      _dirMsg(out.error || 'Sorry, something went wrong. Please try again.', false);
      btn.disabled = false;
      btn.textContent = 'Submit listing';
    }
  } catch (err) {
    _dirMsg('Could not reach Verilay. Please check your connection and try again.', false);
    btn.disabled = false;
    btn.textContent = 'Submit listing';
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

// ── Compare with my last scan ────────────────────────────────────────────────
// Only scans this browser can prove it made (it holds their manage token) are offered; the server checks both tokens.
function _compareName(r) {
  var s = String(r || '').toLowerCase();
  if (s.indexOf('/') !== -1) s = s.split('/').pop();
  return s.replace(/[^a-z]/g, '');    // "2 spendial", "Spendial" and "spendial-v2" all read as "spendial"
}
function findCompareCandidates(report, newId) {
  var name = _compareName((report || {}).repo);
  var list = getHistory().filter(function(h) {
    return h.id && h.id !== newId && h.method !== 'url' && reportToken(h.id);
  });
  list.forEach(function(h) { h._same = !!name && _compareName(h.repo) === name; });
  list.sort(function(a, b) { return (b._same - a._same) || (new Date(b.timestamp) - new Date(a.timestamp)); });
  return list.slice(0, 8);
}
function _compareWhen(ts) {
  var d = new Date(ts);
  if (isNaN(d)) return '';
  return d.toLocaleDateString('en-AU', {day:'numeric', month:'short'}) + ' ' + d.toLocaleTimeString('en-AU', {hour:'2-digit', minute:'2-digit'});
}
// Signed in: the account's own saved scans (any device) join the browser's list; the server checks ownership.
function mergeAccountScans(cands, scans, report, newId) {
  var name = _compareName((report || {}).repo);
  var have = {};
  cands.forEach(function(h) { have[h.id] = true; h._src = 'this browser'; });
  (scans || []).forEach(function(s) {
    if (!s || !s.id || s.id === newId || have[s.id] || s.method === 'url') return;
    have[s.id] = true;
    cands.push({id: s.id, repo: s.repo || 'Unknown', score: s.score || '?', timestamp: s.created_at, method: s.method,
                _src: 'your account', _same: !!name && _compareName(s.repo) === name});
  });
  cands.sort(function(a, b) { return (b._same - a._same) || (new Date(b.timestamp) - new Date(a.timestamp)); });
  return cands.slice(0, 12);
}
async function showCompareOffer() {
  var cands = (window._compareCandidates || []).slice();
  var anchor = document.getElementById('verdict-banner');
  if (!savedReportId || !anchor || !anchor.parentNode) return;
  if (scanFullyIncomplete() || (currentReport && currentReport.preview_only)) return;
  var signedIn = false;
  try {
    var mine = await fetch('/my-scans').then(function(r) { return r.json(); });
    signedIn = !!mine.signed_in;
    if (signedIn) cands = mergeAccountScans(cands, mine.scans, currentReport, savedReportId);
  } catch (e) {}
  window._compareCandidates = cands;
  if (!cands.length) return;
  var old = document.getElementById('compare-card');
  if (old) old.remove();
  var best = cands[0];
  var card = document.createElement('div');
  card.id = 'compare-card';
  // One small line (25 Oct 2026): the comparison opens on its own page, in a new tab, so this report stays as it is.
  card.style.cssText = 'display:flex;gap:8px;align-items:baseline;flex-wrap:wrap;font-size:13px;color:#444441;background:#F1EFE8;' +
    'border-radius:8px;padding:.5rem .8rem;margin-bottom:10px';
  var opts = cands.map(function(h, i) {
    return '<option value="' + i + '">' + esc(h.repo) + ' · ' + esc(_compareWhen(h.timestamp)) + ' · grade ' + esc(h.score) +
      (signedIn ? ' · ' + esc(h._src || 'this browser') : '') + '</option>';
  }).join('');
  card.innerHTML = '<i class="ti ti-arrows-diff" style="font-size:14px;color:var(--pu)"></i><span>' +
      (best._same ? 'You scanned this app before (' + esc(_compareWhen(best.timestamp)) + ', grade ' + esc(best.score) + ').'
                  : 'Compare with an earlier scan?') + '</span>' +
    (cands.length > 1 ? '<select id="compare-pick" aria-label="Earlier scan" style="max-width:100%;border:0.5px solid var(--bdr);border-radius:6px;' +
      'padding:3px 6px;font-size:12px;font-family:inherit;background:white;color:var(--txt)">' + opts + '</select>' : '') +
    '<a href="#" id="compare-go" style="color:var(--pu);font-weight:600;white-space:nowrap">Compare the two scans &rarr;</a>' +
    '<span id="compare-result" style="flex-basis:100%;font-size:12px;color:var(--rdt)"></span>';
  anchor.parentNode.insertBefore(card, anchor.nextSibling);
  document.getElementById('compare-go').onclick = function(ev) {
    ev.preventDefault();
    var pick = document.getElementById('compare-pick');
    runCompare(cands[pick ? (parseInt(pick.value, 10) || 0) : 0]);
  };
}
async function runCompare(prev) {
  var out = document.getElementById('compare-result');
  var btn = document.getElementById('compare-go');
  if (!prev || !out || !btn || btn._busy) return;
  btn._busy = true; btn.textContent = 'Comparing...'; out.textContent = '';
  var win = null;
  try { win = window.open('', '_blank'); } catch (e) {}       // opened now, inside the click, so pop-up blockers allow it
  try {
    var h = reportHeaders(savedReportId, {'Content-Type': 'application/json', 'X-Previous-Token': reportToken(prev.id)});
    var resp = await fetch('/compare-report', {method: 'POST', headers: h,
      body: JSON.stringify({report_id: savedReportId, previous_id: prev.id})});
    var r = await resp.json();
    if (r.error) { out.textContent = r.error; if (win) win.close(); }
    else if (win) { win.location = r.page || ('/compare/' + savedReportId); }
    else { window.location.href = r.page || ('/compare/' + savedReportId); }
  } catch (e) {
    out.textContent = 'The comparison could not be made. Try again.';
    if (win) win.close();
  }
  btn._busy = false; btn.innerHTML = 'Compare the two scans &rarr;';
}
// ── Monitoring early-access offer ─────────────────────────────────────────────
// After a COMPLETE scan graded A: "keep it that way". A test of interest and price; nothing is for sale. A ZIP scan
// gets the same offer worded as an invitation to connect GitHub (a ZIP cannot be watched). Closing it hides it for
// 30 days; joining hides it for good (per browser).
var _MON_OFFER_PLANS = [
  ['basic', 'Basic', 'A$3.99', 'Daily checks for new package problems and exposed keys. AI re-review once a week when your code changed.'],
  ['active', 'Active', 'A$9.99', 'The same daily checks. AI re-review once a day when your code changed.']
];
function _monOfferHidden() {
  try {
    if (localStorage.getItem('verilay_mon_offer_joined')) return true;
    var t = parseInt(localStorage.getItem('verilay_mon_offer_closed') || '0', 10);
    return t && (Date.now() - t) < 30 * 24 * 3600 * 1000;
  } catch (e) { return false; }
}
function showMonitoringOffer() {
  var rep = currentReport || {};
  var score = (rep.health || {}).score;
  if (score !== 'A' || rep.preview_only || (window._incompleteLayers || []).length || !savedReportId) return;
  if (_monOfferHidden() || document.getElementById('mon-offer')) return;
  if (document.getElementById('compare-card')) return;     // one offer at a time: comparing comes first after a rescan
  var isZip = (rep.input_method || currentMethod) === 'zip';
  var repo = !isZip && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(rep.repo || '') ? rep.repo : '';
  var field = 'width:100%;box-sizing:border-box;border:0.5px solid var(--bdr);border-radius:6px;padding:8px 10px;font-size:14px;font-family:inherit;background:white;color:var(--txt)';
  var plans = _MON_OFFER_PLANS.map(function(p, i) {
    return '<label style="display:flex;gap:10px;align-items:flex-start;border:0.5px solid var(--bdr);border-radius:8px;padding:.55rem .7rem;margin-top:.45rem;cursor:pointer;background:white">' +
      '<input type="radio" name="mon-plan" value="' + p[0] + '"' + (i === 0 ? ' checked' : '') + ' style="margin-top:3px">' +
      '<span style="flex:1;min-width:0"><span style="display:flex;justify-content:space-between;gap:8px;font-size:14px;font-weight:600;color:var(--txt)">' +
        '<span>' + p[1] + '</span><span>' + p[2] + '<span style="font-weight:400;color:var(--mut)">/month</span></span></span>' +
      '<span style="display:block;font-size:12px;color:var(--mut);margin-top:2px;line-height:1.45">' + p[3] + '</span></span></label>';
  }).join('');
  var lead = isZip
    ? 'A ZIP upload is a one-off snapshot. Connect your GitHub repository and Verilay can check it every day and email you if your grade drops.'
    : 'Want Verilay to keep watching ' + (repo ? esc(repo) : 'this app') + '? It checks every day and emails you if the grade drops.';
  var box = document.createElement('div');
  box.id = 'mon-offer';
  box.setAttribute('role', 'dialog');
  box.setAttribute('aria-label', 'Keep watching this app');
  box.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:9999;width:calc(100% - 32px);max-width:380px;max-height:calc(100vh - 32px);overflow:auto;' +
    'background:var(--sur);border:0.5px solid var(--pu);border-radius:12px;box-shadow:0 12px 32px rgba(40,30,120,.18);padding:1rem 1.1rem';
  box.innerHTML =
    '<button type="button" id="mon-close" aria-label="Close" style="position:absolute;top:8px;right:10px;border:0;background:transparent;font-size:20px;line-height:1;color:var(--mut);cursor:pointer">&times;</button>' +
    '<div style="font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--pu)">Early access</div>' +
    '<div style="font-size:17px;font-weight:700;color:var(--txt);margin:.15rem 1.5rem .3rem 0">' + (isZip ? 'Keep an eye on this app?' : 'Keep it an A') + '</div>' +
    '<div style="font-size:13px;color:var(--mut);line-height:1.5">' + lead + '</div>' +
    plans +
    (isZip ? '<label for="mon-repo" style="display:block;font-size:12px;font-weight:600;color:var(--put);margin:.7rem 0 3px">GitHub repository <span style="font-weight:400">(optional, owner/name)</span></label>' +
      '<input id="mon-repo" maxlength="120" autocapitalize="none" spellcheck="false" placeholder="yourname/your-app" style="' + field + '">' : '') +
    '<label for="mon-email" style="display:block;font-size:12px;font-weight:600;color:var(--put);margin:.7rem 0 3px">Email</label>' +
    '<input id="mon-email" type="email" maxlength="254" autocomplete="email" style="' + field + '">' +
    '<input id="mon-website" type="text" tabindex="-1" autocomplete="off" style="position:absolute;left:-9999px" aria-hidden="true">' +
    '<button type="button" id="mon-join" class="btn-sm" style="width:100%;margin-top:.7rem;padding:9px 14px">Join early access</button>' +
    '<div id="mon-status" style="font-size:12px;color:var(--rdt);margin-top:.35rem"></div>' +
    '<div style="font-size:11px;color:var(--mut);margin-top:.35rem;line-height:1.45">Not available yet. Nothing is charged: we email you once when it opens.</div>';
  document.body.appendChild(box);
  try { if (typeof plausible === 'function') plausible('Monitoring Offer Shown', {props: {method: isZip ? 'zip' : 'github'}}); } catch (e) {}
  document.getElementById('mon-close').onclick = function() {
    try { localStorage.setItem('verilay_mon_offer_closed', String(Date.now())); } catch (e) {}
    try { if (typeof plausible === 'function') plausible('Monitoring Offer Close'); } catch (e) {}
    box.remove();
  };
  document.getElementById('mon-join').onclick = async function() {
    var btn = this, status = document.getElementById('mon-status');
    var email = (document.getElementById('mon-email').value || '').trim();
    var pick = box.querySelector('input[name="mon-plan"]:checked');
    var plan = pick ? pick.value : 'basic';
    if (!email) { status.textContent = 'Add your email so we can tell you when it opens.'; return; }
    btn.disabled = true; btn.textContent = 'Joining...'; status.textContent = '';
    try {
      var r = await fetch('/monitoring/offer', {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: email, plan: plan, method: isZip ? 'zip' : 'github',
          repo: isZip ? ((document.getElementById('mon-repo') || {}).value || '').trim() : repo,
          website: document.getElementById('mon-website').value})}).then(function(x) { return x.json(); });
      if (r.ok) {
        try { localStorage.setItem('verilay_mon_offer_joined', '1'); } catch (e) {}
        try { if (typeof plausible === 'function') plausible('Monitoring Offer Join', {props: {plan: plan, method: isZip ? 'zip' : 'github'}}); } catch (e) {}
        box.innerHTML = '<button type="button" aria-label="Close" onclick="this.parentNode.remove()" style="position:absolute;top:8px;right:10px;border:0;background:transparent;font-size:20px;line-height:1;color:var(--mut);cursor:pointer">&times;</button>' +
          '<div style="font-size:16px;font-weight:700;color:var(--txt)">You&rsquo;re on the list</div>' +
          '<div style="font-size:13px;color:var(--mut);margin-top:.3rem;line-height:1.5">We&rsquo;ll email you once when monitoring opens. Nothing is charged until you choose to start.</div>';
        return;
      }
      status.textContent = r.error || 'It could not be sent. Try again.';
    } catch (e) {
      status.textContent = 'It could not be sent. Try again.';
    }
    btn.disabled = false; btn.textContent = 'Join early access';
  };
}

// Admin test of the light free scan: open the home page with ?lite=1. The server only honours it for a signed-in
// admin; for anyone else the scan is the normal one. A small note says the test mode is on.
function liteTestMode() {
  try { return new URLSearchParams(window.location.search).get('lite') === '1'; } catch (e) { return false; }
}
function showLiteTestNote() {
  if (!liteTestMode() || document.getElementById('lite-test-note')) return;
  var n = document.createElement('div');
  n.id = 'lite-test-note';
  n.textContent = 'Test mode: light free scan (admin only)';
  n.style.cssText = 'position:fixed;left:16px;bottom:16px;z-index:9998;background:#FEF3C7;color:#92400E;border:0.5px solid #EF9F27;' +
    'border-radius:20px;padding:5px 12px;font-size:12px;font-weight:600';
  document.body.appendChild(n);
}

// ── Verilay Pro (coming soon) ─────────────────────────────────────────────────
// The light free scan gives one fix prompt; this card says how many more are waiting and takes an early-access email.
function proLockedHTML(data) {
  if (data.pro_launch && data.pro_launch.active) return proOfferHTML(data);
  var h = (currentReport && currentReport.health) || {};
  var more = Math.max(0, (h.critical || 0) + (h.warnings || 0) - (data.top_fixes || []).length);
  var lead = more ? (more + ' more fix prompt' + (more === 1 ? ' is' : 's are') + ' ready for this scan.')
                  : 'Want a fix prompt for every finding next time?';
  return '<div id="pro-locked" style="background:var(--pul);border:0.5px solid var(--pu);border-radius:var(--r);padding:.9rem 1rem;margin:.85rem 0">' +
    '<div style="display:flex;gap:10px;align-items:flex-start"><i class="ti ti-lock" style="font-size:20px;color:var(--pu);flex-shrink:0;margin-top:1px"></i>' +
    '<div style="flex:1;min-width:0"><div style="font-size:15px;font-weight:600;color:var(--put)">' + lead + '</div>' +
    '<div style="font-size:13px;color:var(--put);margin-top:3px;line-height:1.55">Verilay Pro, coming soon, will give a ready-to-paste fix prompt for every finding, ' +
    'with fuller explanations, for <strong>A$4.99</strong> a scan. Leave your email and we will tell you when it opens. ' +
    '<a href="/deep-scan#compare" target="_blank" style="color:var(--put)">Compare Free, Pro and Deep</a></div>' +
    '<div id="pro-form" style="display:flex;gap:8px;flex-wrap:wrap;margin-top:.6rem">' +
    '<input id="pro-email" type="email" maxlength="254" autocomplete="email" placeholder="you@example.com" style="flex:1;min-width:180px;' +
    'border:0.5px solid var(--bdr);border-radius:6px;padding:7px 9px;font-size:14px;font-family:inherit;background:white;color:var(--txt)">' +
    '<input id="pro-website" type="text" tabindex="-1" autocomplete="off" style="position:absolute;left:-9999px" aria-hidden="true">' +
    '<button type="button" id="pro-join" class="btn-sm">Join early access</button></div>' +
    '<div id="pro-status" style="font-size:12px;color:var(--put);margin-top:.35rem"></div></div></div></div>';
}
// ── Verilay Pro, free during the launch ──
// The report only says what Pro adds; the 4 questions and the unlock are on /pricing, opened in a new tab so this
// report stays where it is. After unlocking, the Pro scan runs as its own new report (see the ?pro=1 pickup below).
// "30 November" from the offer's end date ('2026-11-30'); '' when there is none.
function launchUntilText(data) {
  var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec((data && data.pro_launch && data.pro_launch.until) || '');
  if (!m) return '';
  var months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  return parseInt(m[3], 10) + ' ' + months[parseInt(m[2], 10) - 1];
}

function proOfferHTML(data) {
  var h = (currentReport && currentReport.health) || {};
  var more = Math.max(0, (h.critical || 0) + (h.warnings || 0) - (data.top_fixes || []).length);
  var lead = more ? more + ' more fix prompt' + (more === 1 ? ' is' : 's are') + ' waiting in Verilay Pro.' : 'Want a fix prompt for every finding?';
  // A bold card with a real button (28 Oct 2026, Moses: the small line got missed in a long report).
  var left = (data.pro_launch && data.pro_launch.left) || 0;
  var until = launchUntilText(data);
  return '<div id="pro-locked" style="background:var(--pul);border:2px solid var(--pu);border-radius:14px;padding:1rem 1.1rem;margin:1rem 0">' +
    '<div style="font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--pu)">&#10024; ' +
    (until ? 'Free until ' + until : 'Free during the launch') + (left ? ' &middot; ' + left + ' left' : '') + '</div>' +
    '<div style="font-size:19px;font-weight:700;color:var(--put);margin:.25rem 0 .3rem;line-height:1.3">' + lead + '</div>' +
    '<div style="font-size:14px;color:var(--put);line-height:1.55">Pro gives a ready-to-paste fix prompt for every finding, reads up to 50 files ' +
    'with a stronger model, and opens as a new report so you can compare the difference. Answer 4 quick questions and it&rsquo;s free' +
    (until ? ' until ' + until + ', then A$4.99 a scan' : '') + '. No card needed.</div>' +
    '<a id="pro-see" href="/pricing#pro" target="_blank" rel="noopener" style="display:inline-block;margin-top:.75rem;background:var(--pu);color:#fff;' +
    'font-size:15px;font-weight:600;padding:10px 18px;border-radius:10px;text-decoration:none">Try Verilay Pro free &rarr;</a></div>';
}

// The same offer, short, near the top of the report once Part 2 has loaded (it starts by itself), so it is seen before
// the long read. Free (light) scans during the launch only.
function showProTopBanner(data) {
  if (!data || !data.lite || !(data.pro_launch && data.pro_launch.active) || document.getElementById('pro-top')) return;
  var anchor = document.getElementById('start-here') || document.getElementById('verdict-banner');
  if (!anchor || !anchor.parentNode) return;
  var h = (currentReport && currentReport.health) || {};
  var more = Math.max(0, (h.critical || 0) + (h.warnings || 0) - (data.top_fixes || []).length);
  var b = document.createElement('div');
  b.id = 'pro-top';
  b.style.cssText = 'display:flex;gap:10px;align-items:center;flex-wrap:wrap;background:var(--pu);color:#fff;border-radius:12px;padding:.7rem 1rem;margin:0 0 10px';
  b.innerHTML = '<span style="font-size:18px">&#10024;</span><span style="flex:1;min-width:200px;font-size:15px;line-height:1.45"><strong>' +
    (more ? more + ' more fix prompt' + (more === 1 ? '' : 's') + ' waiting in Verilay Pro.' : 'Get a fix prompt for every finding with Verilay Pro.') +
    '</strong> ' + (launchUntilText(data) ? 'Free until ' + launchUntilText(data) + ', no card needed.' : 'Free during the launch.') + '</span>' +
    '<a id="pro-see-top" href="/pricing#pro" target="_blank" rel="noopener" style="background:#fff;color:var(--put);font-size:14px;font-weight:700;' +
    'padding:8px 14px;border-radius:9px;text-decoration:none;white-space:nowrap">Try it free &rarr;</a>';
  anchor.parentNode.insertBefore(b, anchor.nextSibling);
  bindProOffer();
}
// Which kind of report this is, in its own colour at the top: Free (grey), Verilay Pro (purple), Deep scan (green).
// Moses, 25 Oct 2026: a free and a Pro report of the same app should be told apart at a glance.
var _TIERS = {
  free: ['Free scan', '#F1EFE8', '#888780', '#444441'],
  pro:  ['Verilay Pro scan', '#EEEDFE', '#534AB7', '#3C3489'],
  deep: ['Deep scan', '#E1F5EE', '#1D9E75', '#085041']
};
function reportTier(data) {
  if (data && data.is_deep_scan) return 'deep';
  return data && data.scan_tier === 'pro' ? 'pro' : 'free';
}
// How the app was shared, next to the kind of scan (28 Oct 2026, Moses: tell at a glance what a scan looked at).
var _METHOD = {github: ['GitHub', 'ti-brand-github'], zip: ['ZIP', 'ti-file-zip'], url: ['Live URL', 'ti-world'],
               github_private: ['Private repo', 'ti-lock']};
function tierBandHTML(data) {
  var t = reportTier(data), c = _TIERS[t], m = _METHOD[data.input_method] || null;
  var what = t === 'deep' ? 'Up to 150 files read, every risky package named'
           : t === 'pro' ? 'Up to 50 files read, a fix prompt for every finding'
           : (data.scan_tier === 'lite' ? 'A quick check, with a fix prompt for the most serious problem' : 'A quick check of your code');
  if (data.input_method === 'url') what = 'What the site shows a browser, not the source code';
  return '<div id="tier-band" data-tier="' + t + '" data-method="' + esc(data.input_method || '') + '" style="background:' + c[1] + ';border-left:4px solid ' + c[2] + ';border-radius:var(--r);' +
    'padding:.55rem .9rem;margin-bottom:10px;display:flex;align-items:baseline;gap:10px;flex-wrap:wrap">' +
    '<span style="font-size:14px;font-weight:700;color:' + c[3] + '">' + c[0] +
    (m ? ' &middot; <i class="ti ' + m[1] + '" style="font-size:14px"></i> ' + m[0] : '') + '</span>' +
    '<span style="font-size:13px;color:' + c[3] + '">' + what + '</span></div>';
}
function showProBadge() {
  var top = document.getElementById('report-content');
  if (!top || document.getElementById('pro-badge')) return;
  var band = document.getElementById('tier-band');
  if (band) { band.outerHTML = tierBandHTML({scan_tier: 'pro'}); return; }
  var b = document.createElement('div');
  b.id = 'pro-badge';
  b.style.cssText = 'display:inline-block;background:var(--pu);color:#fff;font-size:12px;font-weight:600;border-radius:20px;padding:4px 12px;margin-bottom:10px';
  b.textContent = 'Verilay Pro \u00b7 free during launch';
  top.insertBefore(b, top.firstChild);
}

function bindProOffer() {
  ['pro-see', 'pro-see-top'].forEach(function(id) {
    var a = document.getElementById(id);
    if (!a || a._bound) return;
    a._bound = true;
    if (id === 'pro-see') { try { if (typeof plausible === 'function') plausible('Pro Launch Offer Shown'); } catch (e) {} }
    // The report id is known only once the report is saved, so the link is completed when it is clicked.
    a.onclick = function() {
      a.href = '/pricing' + (savedReportId ? '?from=' + encodeURIComponent(savedReportId) : '') + '#pro';
      try { if (typeof plausible === 'function') plausible('Pro Launch Offer Click', {props: {place: id === 'pro-see-top' ? 'top' : 'fixes'}}); } catch (e) {}
    };
  });
}

function bindProEarlyAccess() {
  bindProOffer();
  var btn = document.getElementById('pro-join');
  if (!btn || btn._bound) return;
  btn._bound = true;
  try { if (typeof plausible === 'function') plausible('Pro Offer Shown'); } catch (e) {}
  btn.onclick = async function() {
    var status = document.getElementById('pro-status');
    var email = (document.getElementById('pro-email').value || '').trim();
    if (!email) { status.textContent = 'Add your email so we can tell you when Pro opens.'; return; }
    btn.disabled = true; btn.textContent = 'Joining...'; status.textContent = '';
    try {
      var r = await fetch('/pro/early-access', {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: email, website: document.getElementById('pro-website').value})}).then(function(x) { return x.json(); });
      if (r.ok) {
        document.getElementById('pro-form').style.display = 'none';
        status.textContent = 'You are on the list. We will email you once when Verilay Pro opens.';
        try { if (typeof plausible === 'function') plausible('Pro Early Access Join'); } catch (e) {}
        return;
      }
      status.textContent = r.error || 'It could not be sent. Try again.';
    } catch (e) { status.textContent = 'It could not be sent. Try again.'; }
    btn.disabled = false; btn.textContent = 'Join early access';
  };
}

// Signed in? Link the scans this browser made to the account, so they show on the account page. Proof is each
// report's manage token; the server ignores reports that already belong to someone. Once per browser session.
function claimHistoryReports() {
  try {
    if (sessionStorage.getItem('verilay_claim_tried')) return;
    sessionStorage.setItem('verilay_claim_tried', '1');
  } catch (e) { return; }
  var items = getHistory().filter(function(h) { return h.id && reportToken(h.id); })
    .map(function(h) { return {id: h.id, token: reportToken(h.id)}; }).slice(0, 20);
  if (!items.length) return;
  fetch('/claim-reports', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({reports: items})})
    .catch(function() {});
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
           '<div style="width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#fff;flex-shrink:0;background:' + sc + '">' + h.score + '</div>' +
           '<div style="flex:1;min-width:0">' +
           '<div style="font-size:13px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + (isLatest ? '<span style="font-size:12px;background:var(--pu);color:#fff;border-radius:10px;padding:1px 6px;margin-right:5px;font-weight:600">LATEST</span>' : '') + esc(h.repo) + '</div>' +
           '<div style="font-size:12px;color:var(--mut)">' + timeStr + ' &nbsp;·&nbsp; ' + h.critical + ' critical, ' + h.warnings + ' warnings</div>' +
           '</div>' +
           '<div style="display:flex;gap:6px;flex-shrink:0">' +
           '<button onclick="event.stopPropagation();viewFromHistory(' + idx + ')" style="font-size:12px;padding:3px 9px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);cursor:pointer">View</button>' +

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
  claimHistoryReports();
  showLiteTestNote();
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

  // IT Review Pack -- opens in a new tab. The tab is opened during the click
  // (before any save) so popup blockers allow it, then pointed at the pack.
  var btnIt = document.getElementById('btn-it-review');
  if (btnIt) btnIt.addEventListener('click', function() {
    if (savedReportId) { window.open('/report/' + savedReportId + '/it-review', '_blank'); return; }
    var w = window.open('', '_blank');
    saveReport().then(function() {
      if (savedReportId && w) w.location.href = '/report/' + savedReportId + '/it-review';
      else if (w) w.close();
    });
  });

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

  // Private-repository beta (verilay_private.py): the box shows only to visitors the beta is open to. A visitor who has just chosen a
  // repository (the server remembers the choice for one scan) arrives here with ?private_repo=owner/name and the scan starts.
  (function() {
    fetch("/github/status", {cache: "no-store"}).then(function(r) { return r.json(); }).then(function(s) {
      if (!s || !s.enabled) return;
      var box = document.getElementById("private-beta");
      if (box) box.style.display = "block";
      // the fourth method card and the link in the top box: visible, but only where the beta is open
      ["mc-private", "hero-private"].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.style.display = "";
      });
      var card = document.getElementById("mc-private");
      if (card) card.addEventListener("click", function() { window.location.href = "/github/connect"; });
    }).catch(function() {});
    var m = /[?&]private_repo=([^&]+)/.exec(window.location.search || "");
    if (m) {
      var repo = "";
      try { repo = decodeURIComponent(m[1]); } catch (e) { repo = ""; }
      if (/^[A-Za-z0-9._-]{1,100}[/][A-Za-z0-9._-]{1,100}$/.test(repo)) {
        window._privateRepo = repo;
        currentMethod = "github_private";
        try {
          if (sessionStorage.getItem("verilay_pro_method") === "github_private" && sessionStorage.getItem("verilay_pro_ticket"))
            window._proTicket = sessionStorage.getItem("verilay_pro_ticket");
        } catch (e) {}
        try { history.replaceState(null, "", window.location.pathname); } catch (e) {}
        showForm();
        runAnalysis();
      }
    }
  })();

  // Hero scan box (2026-10-18). Fills the real form, picks the right method and presses the real Analyse
  // button, so nothing about the scan itself changes.
  var heroScan = document.getElementById('hero-scan');
  if (heroScan) heroScan.addEventListener('submit', function(ev) {
    ev.preventDefault();
    var box = document.getElementById('hero-url');
    var v = (box && box.value || '').trim();
    if (!v) { if (box) box.focus(); return; }
    if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(v) && v.split('/')[0].indexOf('.') === -1) v = 'https://github.com/' + v;
    else if (!/^https?:\/\//i.test(v)) v = 'https://' + v;
    var isRepo = /^https?:\/\/(www\.)?(github\.com|gitlab\.com|bitbucket\.org|dev\.azure\.com)\//i.test(v);
    showForm();
    var card = document.getElementById(isRepo ? 'mc-github' : 'mc-url');
    if (card) card.click();
    var field = document.getElementById(isRepo ? 'gh-url' : 'lu');
    if (field) field.value = v;
    try { if (window.plausible) plausible('Hero Scan Start', {props: {kind: isRepo ? 'repo' : 'live-url'}}); } catch (err) {}
    var go = document.getElementById('btn-analyse');
    if (go) go.click();
  });

  var backBtn = document.getElementById('btn-back-hero');
  if (backBtn) backBtn.addEventListener('click', showHero);

  // Funnel tracking: clicks on a similar-project link (free or deep card).
  document.addEventListener('click', function(ev) {
    try {
      var sp = ev.target && ev.target.closest ? ev.target.closest('a.sp-link') : null;
      if (sp && typeof plausible === 'function') plausible('Similar Project Click', {props: {tier: sp.getAttribute('data-tier') || 'free'}});
    } catch (err) {}
  });

  // Funnel tracking: which links people click to reach the deep scan page.
  // Fire-and-forget; never allowed to interfere with the click itself.
  document.addEventListener('click', function(ev) {
    try {
      var a = ev.target && ev.target.closest ? ev.target.closest('a[href^="/deep-scan"]') : null;
      if (!a || typeof plausible !== 'function') return;
      var from = a.closest('#deep-scan-banner') ? 'banner'
               : a.closest('nav, header') ? 'nav'
               : a.closest('#report, #report-content, #report-sections') ? 'report'
               : 'other';
      plausible('Deep Scan CTA Click', {props: {from: from}});
    } catch (err) {}
  });

  // /?scan=owner/repo -- the "Quick scan" link on /account. Fills in the
  // GitHub address and opens the form, but does NOT start the analysis: the
  // user presses Analyse. (Auto-starting from a URL would let any web page
  // trigger paid Claude analyses just by linking here.)
  try {
    var wantedRepo = new URLSearchParams(window.location.search).get('scan');
    if (wantedRepo && /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(wantedRepo)) {
      showForm();
      currentMethod = 'github';
      document.querySelectorAll('.mc').forEach(function(c) { c.classList.remove('sel'); });
      var mcGh = document.getElementById('mc-github');
      if (mcGh) mcGh.classList.add('sel');
      document.querySelectorAll('.ip').forEach(function(pn) { pn.classList.remove('vis'); });
      var pGh = document.getElementById('p-github');
      if (pGh) pGh.classList.add('vis');
      var ghIn = document.getElementById('gh-url');
      if (ghIn) ghIn.value = 'https://github.com/' + wantedRepo;
      var goBtn = document.getElementById('btn-analyse');
      if (goBtn) goBtn.focus();
    }
  } catch (err) {}

  try {
    var proTicket = new URLSearchParams(window.location.search).get('pro') === '1' ? sessionStorage.getItem('verilay_pro_ticket') : '';
    if (proTicket) {
      window._proTicket = proTicket;
      var proMethod = sessionStorage.getItem('verilay_pro_method') || 'github';
      showForm();
      var fs = document.getElementById('form-section');
      var note = document.createElement('div');
      note.id = 'pro-ready';
      note.style.cssText = 'background:var(--pul);border:0.5px solid var(--pu);border-radius:var(--r);padding:.75rem 1rem;margin-bottom:1rem;font-size:14px;color:var(--put);line-height:1.55';
      note.innerHTML = '<strong>Your free Verilay Pro scan is unlocked.</strong> ' +
        (proMethod === 'zip' ? 'Choose your ZIP file again, then press Analyse.'
         : proMethod === 'github_private' ? 'Verilay gave up its access to your private repository after the free scan, so connect it again: ' +
           'the Pro scan starts as soon as you choose the repository. This uses your second private scan today, and the Pro report stays private to this browser. ' +
           '<a href="/github/connect" class="btn-sm" style="display:inline-block;margin-top:.5rem;text-decoration:none">Connect GitHub again</a>'
         : 'Press Analyse to run it.') +
        ' It opens as a new report; your free report keeps its own link.';
      if (fs && fs.children.length > 1) fs.insertBefore(note, fs.children[1]);
      if (proMethod === 'zip') { var mcZip = document.getElementById('mc-zip'); if (mcZip) mcZip.click(); }
    }
  } catch (err) {}

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
  // Real scans take about one to three minutes (bigger repos longer), so count UP instead of promising a countdown
  // that reached "Almost done" after half a minute.
  elapsedSecs++;
  var eta = document.getElementById('prog-eta');
  if (eta) {
    var m = Math.floor(elapsedSecs / 60), s = elapsedSecs % 60;
    eta.textContent = 'Usually 1-3 minutes \u00b7 ' + (m ? m + 'm ' : '') + s + 's so far';
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
  // Guard against stale state from a PREVIOUS analysis in the same tab --
  // these flags/elements only ever get cleared by resetForm() (the "New
  // analysis" buttons), so any path into runAnalysis() that skips that
  // (e.g. a re-scan entry point) would otherwise start this run with
  // _step2Done/_step3Done already true from last time. That makes the
  // very first layer-half to arrive on the NEW run look like BOTH halves
  // are already done -- the progress bar jumps straight past 55%, "mark
  // as verified" buttons unlock before the real analysis is half loaded,
  // and a leftover "ready for Part 2" banner can still be sitting visible
  // from the previous run. Reset explicitly here so every run starts clean
  // regardless of how the user got to this point.
  window._step2Done = false;
  window._step3Done = false;
  window._analysisComplete = false;
  window._scanStreaming = true;       // "Start here" holds the grade until every area is in (28 Oct 2026)
  window._pendingHalfLabel = null;
  window._discoveryHtml = null;
  window._discoverySum = null;
  window._incompleteLayers = [];
  window._layerErrorMsgs = [];
  window._p2AutoStarted = false;      // each new scan starts its own Part 2
  window._moreExtra = []; window._p2Fixes = null; window._startPrompt = '';
  stopTrickle();
  stopP2Trickle();
  var p2banner = document.getElementById('p2-banner');
  if (p2banner) p2banner.style.display = 'none';
  var p2loading = document.getElementById('p2-loading');
  if (p2loading) p2loading.style.display = 'none';
  var p2results = document.getElementById('p2-results');
  if (p2results) p2results.innerHTML = '';
  var stepsBannerReset = document.getElementById('steps23-loading');
  if (stepsBannerReset) stepsBannerReset.style.display = 'none';
  // Undo whatever showAnalysisInterruptedError() may have left behind on a
  // previous run's connection failure (hidden spinner/percentage, the
  // message swapped for an error + retry link) -- otherwise those stay
  // broken for every run after the first interrupted one, not just that run.
  var stepsSpinnerReset = document.getElementById('steps23-spinner');
  if (stepsSpinnerReset) stepsSpinnerReset.style.display = '';
  var stepsPctReset = document.getElementById('steps23-pct');
  if (stepsPctReset) stepsPctReset.style.display = '';
  var stepsMsgReset = document.getElementById('steps23-msg');
  if (stepsMsgReset) stepsMsgReset.textContent = 'Analysing Auth, Config, Database layers...';
  var fd = new FormData();
  fd.append('method', currentMethod);
  if (liteTestMode()) fd.append('lite', '1');   // admin-only test of the light free scan (the server checks the admin)
  // A Pro scan (free during the launch): the one-time ticket from the survey. Kept for this run's Part 2.
  window._proRunTicket = window._proTicket || null;
  if (window._proTicket) {
    fd.append('pro_ticket', window._proTicket); window._proTicket = null;
    try { sessionStorage.removeItem('verilay_pro_ticket'); sessionStorage.removeItem('verilay_pro_method'); } catch (e) {}
    var proReady = document.getElementById('pro-ready'); if (proReady) proReady.remove();
  }
  if (currentMethod === 'github') {
    var url = document.getElementById('gh-url').value.trim();
    if (!url) { showErr('Please enter a GitHub URL'); return; }
    fd.append('github_url', url);
  } else if (currentMethod === 'github_private') {
    var pr = window._privateRepo || '';
    if (!pr) { showErr('Please connect your private repository again.'); return; }
    fd.append('private_repo', pr);
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
    try { if (typeof plausible === 'function') plausible('Analysis Start', {props: {method: currentMethod}}); } catch (e) {}
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
    var errMsg = e.message || 'Something went wrong. Please try again.';
    // Make network errors more helpful
    if (errMsg.includes('Failed to fetch') || errMsg.includes('NetworkError') || errMsg.includes('Load failed')) {
      errMsg = 'Connection interrupted. This can happen with large repos — please try again. If the issue persists, try a smaller repo or ZIP upload.';
    } else if (errMsg.includes('504') || errMsg.includes('timeout')) {
      errMsg = 'Analysis timed out — the repo may be too large. Try a ZIP upload with just the main source files.';
    } else if (errMsg.includes('503')) {
      errMsg = 'Server is busy — please wait 30 seconds and try again.';
    }
    // This used to unconditionally re-show the empty starting form here --
    // fine when written, since step1 used to finish almost instantly, so a
    // stream failure basically always happened DURING the #ld loading
    // screen. Now that step2/step3 can run for minutes, the connection can
    // just as easily drop AFTER step1 already rendered a real partial
    // report -- re-showing the blank form on top of that just stacks it
    // over a still-visible report frozen mid-progress (a real user hit
    // exactly this: the bar sat frozen at 74.5% while the error had nowhere
    // sensible to appear, since #eb lives inside the now-hidden form).
    // Replace the frozen banner in place instead when there's already a
    // report on screen; only fall back to the pristine form when there
    // genuinely isn't one yet.
    if (document.getElementById('rpt').classList.contains('vis')) {
      showAnalysisInterruptedError(errMsg);
    } else {
      document.getElementById('ld').classList.remove('vis');
      document.getElementById('form-section').style.display = 'block';
      showErr(errMsg);
    }
  }
}

function handleStreamEvent(evt) {
  switch(evt.event) {
    case 'status':
      document.getElementById('lm').textContent = evt.data;
      // Also updates the steps23-loading banner's message (see updateStepsLabel)
      // -- #lm lives inside the big #ld loading screen, which gets hidden once
      // step1 renders, so status updates after that point were previously
      // updating an element nobody could see. Harmless before step1 too: the
      // banner just isn't visible yet at that point.
      // Once we know exactly which half is still pending (one of step2/step3
      // has already arrived), keep showing THAT specific "no action needed"
      // message instead of letting this generic heartbeat (sent every ~15s
      // while waiting) overwrite it with vaguer text every time it arrives.
      if (window._pendingHalfLabel) {
        updateStepsLabel(window._pendingHalfLabel);
      } else {
        updateStepsLabel(evt.data);
      }
      break;
    case 'step1':
      stopMsgs();
      document.getElementById('ld').classList.remove('vis');
      // The "still analysing layers" banner (own spinner, own message) takes
      // over from here -- previously built but never actually shown by any
      // code path, so a visitor had no visible sign anything was still
      // happening between step1 rendering and the full report completing.
      var stepsBanner = document.getElementById('steps23-loading');
      if (stepsBanner) stepsBanner.style.display = 'flex';
      updateStepsProgress(15);
      startTrickle(15, 48);
      currentReport = evt.data;
      renderReport(evt.data);
      if (evt.data && evt.data.scan_tier === 'pro') showProBadge();
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
      if (evt.data && evt.data.layers) appendLayers(evt.data.layers);
      window._step2Done = true;
      if (window._step2Done && window._step3Done) {
        window._analysisComplete = true;
        window._pendingHalfLabel = null;
        stopTrickle();
        updateStepsProgress(80);
      } else {
        window._pendingHalfLabel = 'Still analysing API, Frontend, Libraries layers — this finishes automatically, no action needed.';
        updateStepsLabel(window._pendingHalfLabel);
        updateStepsProgress(55);
        startTrickle(55, 75);
      }
      break;
    case 'step3':
      if (evt.data && evt.data.layers) appendLayers(evt.data.layers);
      window._step3Done = true;
      if (window._step2Done && window._step3Done) {
        window._analysisComplete = true;
        window._pendingHalfLabel = null;
        stopTrickle();
        updateStepsProgress(80);
      } else {
        window._pendingHalfLabel = 'Still analysing Auth, Config, Database layers — this finishes automatically, no action needed.';
        updateStepsLabel(window._pendingHalfLabel);
        updateStepsProgress(55);
        startTrickle(55, 75);
      }
      break;
    case 'step2_error':
      // Progressive reveal (backend now yields step2/step3 independently,
      // whichever finishes first) means these two can now arrive minutes
      // apart -- _analysisComplete must only flip once BOTH are resolved
      // (success or error), not after the first one, or the "mark as
      // verified" buttons enable while half the layers haven't loaded yet.
      // The steps23-loading banner's message updates to name whichever
      // half is still actually pending, not a generic placeholder, so
      // "nothing seems to be happening" never happens silently again.
      window._step2Done = true;
      if (window._step2Done && window._step3Done) {
        window._analysisComplete = true;
        window._pendingHalfLabel = null;
        stopTrickle();
        updateStepsProgress(80);
      } else {
        window._pendingHalfLabel = 'Still analysing API, Frontend, Libraries layers — this finishes automatically, no action needed.';
        updateStepsLabel(window._pendingHalfLabel);
        updateStepsProgress(55);
        startTrickle(55, 75);
      }
      layerFailed(evt, ['Auth', 'Config', 'Database']);
      break;
    case 'step3_error':
      window._step3Done = true;
      if (window._step2Done && window._step3Done) {
        window._analysisComplete = true;
        window._pendingHalfLabel = null;
        stopTrickle();
        updateStepsProgress(80);
      } else {
        window._pendingHalfLabel = 'Still analysing Auth, Config, Database layers — this finishes automatically, no action needed.';
        updateStepsLabel(window._pendingHalfLabel);
        updateStepsProgress(55);
        startTrickle(55, 75);
      }
      layerFailed(evt, ['API', 'Frontend', 'Libraries']);
      break;
    case 'discovery':
      // Closest open-source match (server-rendered card). Kept on window so a later re-render of the
      // report does not lose it; replaces the one-line deep-scan pointer in the slot.
      if (evt.data && evt.data.html) {
        window._discoveryHtml = evt.data.html;
        var discSlot = document.getElementById('discovery-slot');
        if (discSlot) discSlot.innerHTML = evt.data.html;
        var tmpd = document.createElement('div');
        tmpd.innerHTML = evt.data.html;
        var spl = tmpd.querySelector('a.sp-link');
        window._discoverySum = spl ? 'Closest: ' + spl.textContent : 'No close open-source match';
        var discSum = document.getElementById('sec-similar-sum');
        if (discSum) discSum.textContent = window._discoverySum;
      }
      break;
    case 'diagram':
      var diagramEl = document.getElementById('architecture-diagram-section');
      var diagramSvg = (evt.data || {}).architecture_diagram;
      var moduleRows = (evt.data || {}).module_purpose_rows;
      if (diagramEl && diagramSvg) {
        // Purpose caption reuses step1's summary (currentReport.summary) --
        // a separate, reliable call, not subject to the same truncation
        // risk as the per-box labels in the diagram itself.
        diagramEl.innerHTML = diagramCardHTML(currentReport && currentReport.summary, diagramSvg, moduleRows);
      }
      // Mirrored onto currentReport so saveToHistory() (triggered by the
      // 'saved' event right after this one) captures it consistently.
      if (currentReport) {
        currentReport.architecture_diagram = diagramSvg;
        currentReport.module_purpose_rows = moduleRows;
      }
      updateStepsProgress(90);
      break;
    case 'saved':
      updateStepsProgress(97);
      savedReportId = evt.data.report_id;
      storeReportToken(evt.data.report_id, evt.data.manage_token);
      if (currentReport && currentReport.private) {
        // The server checks the report's own private key before it lets this browser open the report later.
        try { fetch('/private-report/claim/' + encodeURIComponent(evt.data.report_id), {method: 'POST', headers: {'X-Report-Token': evt.data.manage_token}}); } catch (e) {}
      }
      currentVerifications = {};  // Reset verifications for new report
      // The report-grounded Ask Verilay box (in the "Have questions" card)
      // renders disabled from step1 onward, since savedReportId doesn't
      // exist yet -- enable it now that there's a real report_id to ask
      // questions about.
      var reportAskInput = document.getElementById('report-ask-input');
      var reportAskBtn = document.getElementById('report-ask-btn');
      if (reportAskInput && reportAskBtn) {
        reportAskInput.disabled = false;
        reportAskInput.placeholder = 'Ask a question about your results...';
        reportAskBtn.disabled = false;
        reportAskBtn.style.opacity = '1';
        reportAskBtn.style.cursor = 'pointer';
      }
      // Earlier scans to offer for "compare", read BEFORE this one replaces its namesake in the history
      window._compareCandidates = findCompareCandidates(currentReport, savedReportId);
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
      // Offer a listing in the app directory (GitHub scans only; the server checks everything again).
      if (currentMethod === 'github') showDirectoryCard(evt.data.report_id);

      // Show waitlist nudge after 3+ analyses
      var analysisCount = parseInt(localStorage.getItem('verilay_analysis_count') || '0') + 1;
      localStorage.setItem('verilay_analysis_count', analysisCount);
      if (analysisCount >= 3 && !localStorage.getItem('verilay_waitlist_shown')) {
        setTimeout(function() { showWaitlistNudge(analysisCount); }, 2000);
      }
      // Show feedback widget and star prompt
      var fw = document.getElementById('feedback-widget');
      if (fw) fw.style.display = 'block';
      setTimeout(showRatingNudge, 60000);              // or after a minute of reading, if nothing was copied
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
      window._scanStreaming = false;
      if (typeof refreshStartHere === 'function') refreshStartHere();
      stopTrickle();
      updateStepsProgress(100);
      var lb = document.getElementById('steps23-loading');
      if (lb) lb.style.display = 'none';
      // Part 2 (the fix prompts, and the Verilay Pro line after a free scan) now starts by itself (28 Oct 2026): behind a
      // "Yes, run Part 2" button many people never saw their fix prompt or the Pro offer. The button stays as the
      // fallback when nothing could be checked, or if the automatic start fails.
      var p2 = document.getElementById('p2-banner');
      if (p2 && !(currentReport && currentReport.preview_only)) {
        if (!scanFullyIncomplete() && !window._p2AutoStarted) {
          window._p2AutoStarted = true;
          try { if (typeof plausible === 'function') plausible('Part 2 Auto Start'); } catch (e) {}
          setTimeout(function() { runPart2().catch(function() { p2.style.display = 'block'; }); }, 400);
        } else {
          p2.style.display = 'block';
        }
      }
      showCompareOffer();
      setTimeout(showMonitoringOffer, 1500);
      break;
    case 'error':
      window._scanStreaming = false;
      stopTrickle();
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

// Tied to real milestones the backend actually reaches (step1 shown, one
// layer-half done, both halves done, diagram computed, report saved) --
// not a fake timer. A time-based bar would routinely lie now that a real
// analysis can take anywhere from 30s to a few minutes depending on repo
// size and how much Claude has to generate.
function updateStepsProgress(pct) {
  var bar = document.getElementById('steps23-bar');
  var pctEl = document.getElementById('steps23-pct');
  if (bar) bar.style.width = pct + '%';
  if (pctEl) pctEl.textContent = pct + '%';
}

// The two slow stretches (waiting for the first Claude layer-call, then
// waiting for the second) can genuinely run 30s-several minutes with NO
// real milestone in between -- the bar just sat still the whole time.
// This creeps it slowly toward a CEILING it can never reach or pass, so
// there's always visible motion without ever claiming to be further along
// than is actually known. The real milestone (55%/80%) always lands ABOVE
// the ceiling, so the jump when it actually happens is still a genuine,
// visible increase, never a step backward.
var trickleTimer = null;
function startTrickle(fromPct, ceilingPct) {
  stopTrickle();
  var current = fromPct;
  trickleTimer = setInterval(function() {
    var remaining = ceilingPct - current;
    if (remaining <= 0.5) return;
    current += remaining * 0.08;
    updateStepsProgress(Math.round(current * 10) / 10);
  }, 1500);
}
function stopTrickle() {
  if (trickleTimer) { clearInterval(trickleTimer); trickleTimer = null; }
}

// The connection to the SSE stream itself can die after a partial report
// is already showing (not just a backend-reported step2_error/step3_error,
// which handleStreamEvent() already covers). Reuses the same steps23-loading
// banner the user was already looking at -- swaps its spinner+bar for the
// error message and a retry link in place, rather than discarding the
// partial report and reopening the empty starting form on top of it.
function showAnalysisInterruptedError(msg) {
  stopTrickle();
  var banner = document.getElementById('steps23-loading');
  if (banner) banner.style.display = 'flex';
  var spinner = document.getElementById('steps23-spinner');
  if (spinner) spinner.style.display = 'none';
  var pctEl = document.getElementById('steps23-pct');
  if (pctEl) pctEl.style.display = 'none';
  var msgEl = document.getElementById('steps23-msg');
  if (msgEl) {
    msgEl.innerHTML = esc(msg) + ' <a href="#" onclick="resetForm(true);return false;" style="color:var(--put);text-decoration:underline;font-weight:600">Try again</a>';
  }
}

// Part 2 (/analyse-step4) is a single request/response, not the SSE stream
// analyse-stream() uses -- there are no real milestones to hook a bar to at
// all, just one fetch() that resolves once at the end. Same honest-creep
// approach as above (own timer, own bar), calibrated for the "15-20
// seconds" the banner already tells the user to expect: it stays visibly
// moving toward a ceiling it never reaches, then the loading block gets
// replaced by the real results the moment the response actually arrives --
// never claims done before it is.
var p2TrickleTimer = null;
function startP2Trickle() {
  stopP2Trickle();
  var current = 5;
  updateP2Progress(current);
  p2TrickleTimer = setInterval(function() {
    var remaining = 90 - current;
    if (remaining <= 0.5) return;
    current += remaining * 0.1;
    updateP2Progress(Math.round(current * 10) / 10);
  }, 1200);
}
function stopP2Trickle() {
  if (p2TrickleTimer) { clearInterval(p2TrickleTimer); p2TrickleTimer = null; }
}
function updateP2Progress(pct) {
  var bar = document.getElementById('p2-bar');
  if (bar) bar.style.width = pct + '%';
}

function resetForm(goToForm) {
  // Clear the report
  stopTrickle();
  stopP2Trickle();
  document.getElementById('rpt').classList.remove('vis');
  if (document.getElementById('report-content'))
    document.getElementById('report-content').innerHTML = '';
  if (document.getElementById('report-sections'))
    document.getElementById('report-sections').innerHTML = '';
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
  var dirCard = document.getElementById('directory-card');
  if (dirCard) dirCard.remove();

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

// Ported from ASK_PAGE_HTML's inline script (app.py) -- that page is a fully
// standalone route with no access to this file, so it keeps its own copy;
// this is the one app.js needs for rendering a report-grounded Ask Verilay
// answer inline without leaving the page.
function inl(s) { return s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>'); }
function md(t) {
  var ls = esc(t).split('\n'), out = [], lt = null;
  function cl() { if (lt) { out.push('</' + lt + '>'); lt = null; } }
  function op(type) { if (lt !== type) { cl(); out.push('<' + type + '>'); lt = type; } }
  for (var i = 0; i < ls.length; i++) {
    var l = ls[i];
    if (/^###\s+/.test(l)) { cl(); out.push('<h4>' + inl(l.replace(/^###\s+/, '')) + '</h4>'); }
    else if (/^##\s+/.test(l)) { cl(); out.push('<h3>' + inl(l.replace(/^##\s+/, '')) + '</h3>'); }
    else if (/^#\s+/.test(l)) { cl(); out.push('<h3>' + inl(l.replace(/^#\s+/, '')) + '</h3>'); }
    else if (/^---+\s*$/.test(l)) { cl(); out.push('<hr>'); }
    else if (/^\s*[-*]\s+/.test(l)) { op('ul'); out.push('<li>' + inl(l.replace(/^\s*[-*]\s+/, '')) + '</li>'); }
    else if (/^\s*\d+\.\s+/.test(l)) { op('ol'); out.push('<li>' + inl(l.replace(/^\s*\d+\.\s+/, '')) + '</li>'); }
    else if (l.trim() === '') { cl(); }
    else { cl(); out.push('<p>' + inl(l) + '</p>'); }
  }
  cl();
  return out.join('');
}

function gradeFromCounts(critical, warnings) {
  if (critical >= 6) return 'F';
  if (critical >= 3) return 'D';
  if (critical >= 1) return 'C';
  if (warnings >= 4) return 'C';
  if (warnings >= 1) return 'B';
  return 'A';
}

function healthFromLayers(layers, data) {
  var c = 0, w = 0, p = 0;
  (layers || []).forEach(function(l) {
    (((l.expert || {}).findings) || []).forEach(function(f) {
      if (f.severity === 'critical') c++;
      else if (f.severity === 'warning') w++;
      else if (f.severity === 'passing') p++;
    });
  });
  // Same floor the server applies when it saves a report: a scanner-confirmed
  // fact (an exposed key, a named CVE against a version we can read) can't be
  // talked under by counting layer-finding objects — the Libraries layer only
  // ever holds ONE finding object summarising all OSV vulnerabilities, so
  // counting objects alone showed "1 critical" for a report OSV rated 16
  // critical. Mirrors analyse_stream()'s max(_crit, scan_critical,
  // osv_critical) so the live header, Part 2's input, and the saved report
  // can never disagree with each other again.
  var scan = (data && data.secret_scan) || {};
  var osv = (data && data.osv_scan) || {};
  var authz = (data && data.authz_scan) || {};
  c = Math.max(c, scan.critical || 0, osv.critical || 0, Math.min(authz.critical || 0, 5));  // same cap as the server (GRADE_CAP)
  w = Math.max(w, scan.warnings || 0, osv.warnings || 0);
  var score = gradeFromCounts(c, w);
  var limited = !enoughReadForA(data);
  if (score === 'A' && limited) score = 'B';          // same rule as the server's grade_with_coverage (31 Oct 2026)
  return { critical: c, warnings: w, passing: p, score: score, limited_coverage: limited };
}
function limitedCoverageHTML(data) {
  return '<div style="background:#FEF9C3;border:0.5px solid #EAB308;border-radius:var(--r);padding:.7rem 1rem;margin-bottom:10px;font-size:13px;' +
    'line-height:1.6;color:#854D0E"><strong>Only ' + esc(String(data.files_read)) + ' of ' + esc(String(data.files_total)) +
    ' files could be read.</strong> So this report can&rsquo;t give an A: nothing found here doesn&rsquo;t mean nothing is wrong in the ' +
    'files that weren&rsquo;t read.</div>';
}
// An A needs enough of the code read: half the files, or 10 when there are more than 20 (app.py enough_read_for_a).
function enoughReadForA(data) {
  var read = parseInt((data && data.files_read) || 0, 10), total = parseInt((data && data.files_total) || 0, 10);
  if (!(read > 0) || !(total > 0)) return true;
  return read >= Math.min(10, Math.floor((total + 1) / 2));
}

// "4 of 6": areas with a real result (not "Not checked"), out of the six.
function areasCheckedText() {
  var names = Object.keys(currentLayers || {});
  var inc = window._incompleteLayers || [];
  var ok = names.filter(function(k) { return currentLayers[k] && currentLayers[k].status !== 'not_checked' && inc.indexOf(k) === -1; }).length;
  return ok + ' of 6';
}
function healthCardsHTML(h, hasLayers, isPreview) {
  // The third box says how much of the app was checked ("6 of 6"). The old "no issues seen" count was easy to misread
  // next to the grade; "passing" was never used because the scan can only say what it saw.
  var hlbls = ['critical', 'warnings', 'areas checked', 'score'];
  if (isPreview) {
    return hlbls.map(function(lbl) {
      var val = lbl === 'score' ? 'n/a' : '–';
      var sub = lbl === 'score' ? 'not graded' : lbl;
      return '<div class="hc" style="background:var(--bll)"><div style="font-size:18px;font-weight:600;color:var(--blt)">' + val + '</div><div style="font-size:12px;color:var(--blt);margin-top:1px">' + sub + '</div></div>';
    }).join('');
  }
  if (!hasLayers) {
    return hlbls.map(function(lbl) {
      var val = lbl === 'score' ? '···' : '–';
      var sub = lbl === 'score' ? 'calculating' : lbl;
      return '<div class="hc" style="background:var(--bll)"><div style="font-size:18px;font-weight:600;color:var(--blt)">' + val + '</div><div style="font-size:12px;color:var(--blt);margin-top:1px">' + sub + '</div></div>';
    }).join('');
  }
  var hvals = [h.critical || 0, h.warnings || 0, areasCheckedText(), h.score || '?'];
  var scoreBgCol = h.score === 'A' ? ['#E1F5EE', '#085041'] :
                   h.score === 'B' ? ['#EFF6FF', '#1D4ED8'] :
                   h.score === 'C' ? ['#FEF9C3', '#854D0E'] :
                   h.score === 'D' ? ['#FEF2F2', '#991B1B'] :
                   h.score === 'F' ? ['#FEF2F2', '#7F1D1D'] : ['var(--bll)', 'var(--blt)'];
  var hcols = [['var(--rdl)', 'var(--rdt)'], ['var(--orl)', 'var(--ort)'], ['var(--grl)', 'var(--grt)'], scoreBgCol];
  return hvals.map(function(v, i) {
    return '<div class="hc" style="background:' + hcols[i][0] + '"><div style="font-size:18px;font-weight:600;color:' + hcols[i][1] + '">' + v + '</div><div style="font-size:12px;color:' + hcols[i][1] + ';margin-top:1px">' + hlbls[i] + '</div></div>';
  }).join('');
}

function scoreBannerHTML(score, hasLayers, isPreview, crit) {
  if (isPreview) {
    return '<div style="background:var(--bll);border:0.5px solid var(--blt);border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px;font-size:13px;line-height:1.6;color:var(--blt)"><i class="ti ti-eye"></i> <strong>This was a quick URL preview — not a graded analysis.</strong> A URL scan only sees what the site serves to a browser, not your source code. To get a real score, scan your GitHub repo or upload a ZIP.</div>';
  }
  if (!hasLayers) {
    return '<div style="background:var(--bll);border:0.5px solid var(--blt);border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px;font-size:13px;line-height:1.6;color:var(--blt)"><i class="ti ti-loader"></i> Analysing your codebase — your score appears once all layers are checked.</div>';
  }
  if (!score || score === 'A') return '';
  var scoreBg = '', scoreBdr = '', scoreMsg = '';
  if (score === 'B') {
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
  } else if (score === 'C') {
    scoreBg = '#FEF9C3'; scoreBdr = '#EAB308';
    var what = crit === 0 ? 'warnings' : 'critical issues';     // a C can come from warnings alone
    scoreMsg = '🎯 <strong>Score C — Almost there.</strong> ' + (crit === 0 ? 'There are no critical issues; fix the warnings above' : 'Fix the critical issues above') +
      ' and you will reach B. That is the realistic goal for AI-built apps — not A.<br><br>' +
      '<strong>Your path to B:</strong><br>' +
      '1. Use the advice prompts below to investigate each of the ' + what + '<br>' +
      '2. Take findings to your AI builder and ask them to verify<br>' +
      '3. Paste their response back here to update your score<br>' +
      '4. Once the ' + what + ' are verified or fixed — re-run for updated score';
  } else if (score === 'D' || score === 'F') {
    scoreBg = '#FEF2F2'; scoreBdr = '#EF4444';
    scoreMsg = '🎯 <strong>Score ' + score + ' — Not ready to launch.</strong> ' + (crit === 0 ? 'Work through the warnings' : 'Fix critical issues first') + ' using the advice prompts below. Realistic goal is B — safe for real users. Getting to A requires a professional developer security review.';
  }
  return '<div style="background:' + scoreBg + ';border:0.5px solid ' + scoreBdr + ';border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px;font-size:13px;line-height:1.6">' + scoreMsg + '</div>';
}

// Areas with no result ("Not checked"). The grade covers the other areas and is never above B; only when NO area has
// a result is the scan "incomplete" with no grade (same rule as the server's grade_with_unchecked).
function scanFullyIncomplete() {
  var inc = window._incompleteLayers || [];
  var checked = Object.keys(currentLayers).filter(function(k) {
    return currentLayers[k] && currentLayers[k].status !== 'not_checked' && inc.indexOf(k) === -1;
  });
  return inc.length > 0 && checked.length === 0;
}
function updateHealthDisplay() {
  var layers = Object.keys(currentLayers).map(function(k) { return currentLayers[k]; });
  var notChecked = window._incompleteLayers || [];
  if (!layers.length && !notChecked.length) return;
  var full = scanFullyIncomplete();
  var inc = full ? notChecked : [];
  var h = layers.length ? healthFromLayers(layers, currentReport) : {critical: 0, warnings: 0, passing: 0, score: null};
  if (notChecked.length && h.score === 'A') h.score = 'B';
  if (currentReport) currentReport.health = h;
  var grid = document.getElementById('health-grid');
  if (grid) {
    grid.innerHTML = healthCardsHTML(h, true);
    if (inc.length && grid.lastElementChild) {
      // The grade card must not show a letter that was worked out from only some of the layers.
      grid.lastElementChild.style.background = '#F1EFE8';
      grid.lastElementChild.innerHTML = '<div style="font-size:18px;font-weight:600;color:#444441">n/a</div><div style="font-size:12px;color:#444441">incomplete</div>';
    }
  }
  var banner = document.getElementById('score-banner');
  if (banner) banner.innerHTML = inc.length ? '' : scoreBannerHTML(h.score, true, false, h.critical);
  var vb = document.getElementById('verdict-banner');
  if (vb) vb.innerHTML = inc.length ? incompleteBannerHTML(inc) : (notChecked.length ? notCheckedBannerHTML(notChecked) :
    (h.limited_coverage && currentReport ? limitedCoverageHTML(currentReport) : ''));
  refreshStartHere();
  refreshAskChips(h);
  var ls = document.getElementById('sec-layers-sum');
  if (ls) ls.textContent = layersSummaryText(h, notChecked);
}
function notCheckedBannerHTML(names) {
  return '<div style="background:#F1EFE8;color:#444441;border-radius:var(--r);padding:.7rem 1rem;margin:-2px 0 10px;font-size:13px;line-height:1.55">' +
    '<strong>Not checked this time: ' + esc(names.join(', ')) + '.</strong> The grade covers the other areas, and a scan with an area ' +
    'not checked is never graded above B. Nothing there should be read as a pass. Run the analysis again to check them.</div>';
}

function fileBreakdownHTML(data) {
  var bd = data.file_breakdown || [];
  var total = data.files_total || 0;
  if (!bd.length || total < 8) return '';  // skip for tiny apps where it adds nothing

  // Hardcoded, zero-cost explanations. Two registers: plain (Learner) and terse (Expert).
  var CAT = {
    visual: {label: 'Visual & pages',
      plain: 'The buttons, screens and layouts people see and click. These run safely inside your app and don\u2019t expose your data.',
      expert: 'UI components, pages, styles \u2014 presentational, no data access.'},
    data: {label: 'Data & logins',
      plain: 'The parts that handle accounts, user data and connections to other services. This is where security actually matters \u2014 and it\u2019s what Verilay focuses on.',
      expert: 'Auth, DB, API routes, server & webhook logic \u2014 the security-relevant surface.'},
    config: {label: 'Settings & config',
      plain: 'How your app is set up and configured \u2014 the behind-the-scenes settings that tell it how to run.',
      expert: 'Env, build, config & tooling files.'},
    libs: {label: 'Building blocks',
      plain: 'Ready-made pieces from libraries you didn\u2019t write yourself. Widely used and maintained by others.',
      expert: 'Vendored / generated / dependency files (not your code).'},
    other: {label: 'Other',
      plain: 'Everything else \u2014 documentation, images and miscellaneous files.',
      expert: 'Docs, assets and uncategorised files.'}
  };

  var rows = bd.map(function(b) {
    var c = CAT[b.key]; if (!c) return '';
    return '<div class="fb-row" style="display:flex;gap:10px;padding:.5rem 0;border-top:0.5px solid var(--bdr)">' +
      '<div style="min-width:44px;font-weight:700;font-size:15px;color:var(--txt)">' + b.count + '</div>' +
      '<div style="flex:1">' +
        '<div style="font-size:14px;font-weight:600;margin-bottom:1px">' + esc(c.label) + '</div>' +
        '<div class="fb-plain" style="font-size:13px;color:var(--mut);line-height:1.5">' + esc(c.plain) + '</div>' +
        '<div class="fb-expert" style="font-size:13px;color:var(--mut);line-height:1.5;display:none">' + esc(c.expert) + '</div>' +
      '</div></div>';
  }).join('');

  var h = '<div style="border:0.5px solid var(--bdr);border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap">';
  h += '<button onclick="toggleBreakdown()" id="fb-toggle" style="font-size:14px;font-weight:600;background:none;border:none;color:var(--txt);cursor:pointer;padding:0;display:flex;align-items:center;gap:6px">' +
       '<span id="fb-caret">\u25b8</span> What your app is made of (' + total + ' files)</button>';
  h += '<button onclick="toggleBreakdownMode()" id="fb-mode" style="font-size:12px;padding:3px 10px;border-radius:6px;border:0.5px solid var(--bdr);background:var(--bg);color:var(--mut);cursor:pointer;display:none">Developer view</button>';
  h += '</div>';
  h += '<div id="fb-body" style="display:none;margin-top:8px">';
  h += '<div style="font-size:13px;color:var(--mut);line-height:1.55;margin-bottom:6px">Most of your app is the safe internal machinery \u2014 the visual parts and building blocks that run inside and don\u2019t expose your data. The parts that matter for safety are the smaller <strong>Data &amp; logins</strong> set, which is what Verilay checks first.</div>';
  h += rows;
  h += '</div></div>';
  return h;
}

function toggleBreakdown() {
  var b = document.getElementById('fb-body');
  var c = document.getElementById('fb-caret');
  var m = document.getElementById('fb-mode');
  if (!b) return;
  var open = b.style.display === 'none';
  b.style.display = open ? 'block' : 'none';
  if (c) c.textContent = open ? '\u25be' : '\u25b8';
  if (m) m.style.display = open ? 'inline-block' : 'none';
}

function toggleBreakdownMode() {
  var btn = document.getElementById('fb-mode');
  var toExpert = btn.textContent === 'Developer view';
  document.querySelectorAll('.fb-plain').forEach(function(e){ e.style.display = toExpert ? 'none' : 'block'; });
  document.querySelectorAll('.fb-expert').forEach(function(e){ e.style.display = toExpert ? 'block' : 'none'; });
  btn.textContent = toExpert ? 'Simple view' : 'Developer view';
}

function diagramCardHTML(summary, diagramSvg, moduleRows) {
  // Shared by the initial render (architectureDiagramHTML) and the live
  // 'diagram' SSE update (handleStreamEvent) so the merged-card markup is
  // built in exactly one place. One card, one toggle: the diagram itself
  // always shows (it's the "wow" moment, shouldn't need a click), the
  // module list is the supplementary detail that's collapsed -- same
  // pattern as "What your app is made of" (toggleBreakdown), own ids so
  // the two toggles don't collide.
  if (!diagramSvg) return '';
  var purposeLine = summary
    ? '<div style="font-size:13px;color:var(--mut);margin-bottom:.75rem">' + esc(summary) + '</div>' : '';
  var moduleBlock = moduleRows ? (
    '<div style="margin-top:.75rem;padding-top:.6rem;border-top:0.5px solid var(--bdr)">' +
    '<button onclick="toggleModulePurpose()" id="mp-toggle" style="font-size:13px;font-weight:600;background:none;border:none;color:var(--pu);cursor:pointer;padding:0;display:flex;align-items:center;gap:6px">' +
    '<span id="mp-caret">▸</span> What each part does</button>' +
    '<div id="mp-body" style="display:none;margin-top:.5rem">' + moduleRows + '</div></div>'
  ) : '';
  return '<div class="st">How Your App Fits Together</div><div class="card">' + purposeLine + diagramSvg + moduleBlock + '</div>';
}

function toggleModulePurpose() {
  var b = document.getElementById('mp-body');
  var c = document.getElementById('mp-caret');
  if (!b) return;
  var open = b.style.display === 'none';
  b.style.display = open ? 'block' : 'none';
  if (c) c.textContent = open ? '▾' : '▸';
}

function architectureDiagramHTML(data) {
  // Empty until the 'diagram' SSE event arrives (it's computed server-side
  // after step2/step3 finish, not available yet at the initial step1 render)
  // -- the 'diagram' case in handleStreamEvent fills the container in later.
  return diagramCardHTML(data.summary, data.architecture_diagram, data.module_purpose_rows);
}

// One line on FREE reports of GitHub apps: similar-project discovery is a deep scan feature.
function discoveryTeaserHTML(data) {
  if (!data || data.preview_only || (data.input_method && data.input_method !== 'github')) return '';
  return '<div style="font-size:13px;color:var(--mut);margin:.75rem 0;padding:.6rem .85rem;background:var(--sur);' +
         'border:0.5px solid var(--bdr);border-radius:var(--r)">Want to find out what similar apps already exist? ' +
         'The <a href="/deep-scan" style="color:var(--pu);font-weight:600">deep scan</a> includes a list of similar ' +
         'open-source projects.</div>';
}

function filesCoverageHTML(data) {
  var analysed = data.files_analysed || [];
  var read = data.files_read || analysed.length;
  if (!read) return '';

  var listItems = analysed.map(function(p) {
    return '<div style="font-family:monospace;font-size:12px;color:var(--mut);padding:2px 0">' + esc(p) + '</div>';
  }).join('');

  // URL scans only see what the site serves to a browser (built/minified output),
  // not the source tree — so we never show an "X of N" coverage claim for them.
  if (data.input_method === 'url') {
    var u = '<div style="border:0.5px solid var(--bdr);border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px;font-size:13px">';
    u += '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px">';
    u += '<div><strong>URL preview — ' + read + ' file' + (read === 1 ? '' : 's') + ' served by the live site</strong></div>';
    if (analysed.length) {
      u += '<button onclick="toggleFileList()" id="filelist-toggle" style="font-size:12px;padding:3px 10px;border-radius:6px;border:0.5px solid var(--bdr);background:var(--bg);color:var(--txt);cursor:pointer">Show files</button>';
    }
    u += '</div>';
    u += '<div id="filelist" style="display:none;margin-top:8px;max-height:200px;overflow:auto;border-top:0.5px solid var(--bdr);padding-top:8px">' + listItems + '</div>';
    u += '<div style="color:var(--mut);font-size:12px;line-height:1.5;margin-top:8px">';
    u += 'A URL scan only sees what the site serves to a browser — usually built or minified output, not your source code. This is a quick preview, not a full review.';
    if (read <= 3) {
      u += ' <strong>This site served very little analysable code, so there\'s not much here to go on.</strong>';
    }
    u += ' To properly check your own app, scan its GitHub repo or upload a ZIP — that\'s where Verilay reads your actual source.';
    u += '</div>';
    u += '</div>';
    return u;
  }

  var total = data.files_total || read;
  var uncovered = Math.max(0, total - read);
  var partial = uncovered >= 15;

  var html = '<div style="border:0.5px solid var(--bdr);border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px;font-size:13px">';
  html += '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px">';
  // Two different depths now, and conflating them undersells the product.
  // scanned  = every file, read directly, checked for exposed keys (certain)
  // read     = the sample Claude reads for the layer analysis (judgement)
  var scan = data.secret_scan || {};
  var scanned = scan.files_scanned || 0;
  html += '<div><strong>Files analysed: ' + read + ' of ' + total + '</strong>';
  if (scanned > read) {
    html += '<span style="color:var(--gr)"> &nbsp;·&nbsp; all ' + scanned + ' checked for exposed keys</span>';
  }
  html += '</div>';
  if (analysed.length) {
    html += '<button onclick="toggleFileList()" id="filelist-toggle" style="font-size:12px;padding:3px 10px;border-radius:6px;border:0.5px solid var(--bdr);background:var(--bg);color:var(--txt);cursor:pointer">Show files</button>';
  }
  html += '</div>';
  html += '<div id="filelist" style="display:none;margin-top:8px;max-height:200px;overflow:auto;border-top:0.5px solid var(--bdr);padding-top:8px">' + listItems + '</div>';

  html += '<div style="color:var(--mut);font-size:12px;line-height:1.5;margin-top:8px">';
  if (scanned > read) {
    html += '<strong>Every one of your ' + scanned + ' files was checked for exposed keys and passwords.</strong> That check reads the actual contents of each file, so its results are facts, not estimates.';
    html += '<br><br>The <strong>deeper review</strong> — how your login, database, settings and code fit together — covers the ' + read + ' files most likely to carry risk. That part is a first pass, not a full audit, and it cannot run your code or read your live database dashboard. Treat it as a starting point rather than a clean bill of health.';
  } else if (partial) {
    html += 'Verilay reads the files most likely to carry security risk — a first-pass scan, not a full audit. <strong>' + uncovered + ' files were not analysed.</strong> Static scans also cannot run your code or read your live database dashboard, so treat this as a starting point, not a clean bill of health.';
  } else {
    html += 'Near-complete coverage of this codebase. This is still a first-pass surface scan — it cannot run your code or read your live database dashboard, so for apps handling real users or payments, get a deeper review before launch.';
  }
  html += '</div>';

  // This is the free tier's own live view -- a deep scan report never
  // renders through this function (it's a background job that lands
  // straight on the saved page), so this CTA can be unconditional.
  html += '<div style="font-size:12px;color:var(--txt);margin-top:8px">';
  if (scanned > read) {
    html += 'Want the layer analysis extended across all ' + scanned + ' files, plus the exact dependency package names and fixes? That\'s what the <a href="/deep-scan" style="color:var(--pu)">deep scan</a> adds.';
  } else if (partial) {
    html += 'Want the other ' + uncovered + ' files reviewed too? The <a href="/deep-scan" style="color:var(--pu)">deep scan</a> reads up to 150 files and hands you exact dependency fixes.';
  } else {
    html += 'Want exact dependency package names and fixes, plus unlimited re-scans for 30 days? Check out the <a href="/deep-scan" style="color:var(--pu)">deep scan</a>.';
  }
  html += '</div>';

  html += '<div style="color:var(--mut);font-size:12px;line-height:1.5;margin-top:8px">For apps handling real users or sensitive data, a deeper review is worth it before launch — a dependency scanner (e.g. Snyk), AI code review (e.g. CodeRabbit), or a developer security audit.</div>';

  html += '</div>';
  html += verifiedFindingsHTML(data);
  html += osvFindingsHTML(data);
  html += authzFindingsHTML(data);
  return html;
}

// OSV.dev dependency check. Free tier only ever gets a COUNT here — never
// package names or CVE ids, that's the deep scan's job (Decision 6). Don't
// add per-package detail to this card even if it becomes available later
// without also updating the backend teaser dict, or the free/paid boundary
// silently disappears on the frontend while the backend still thinks it's
// enforcing it.
// "Who can do what" (Supabase apps): the free scan shows counts and one example; the deep scan report
// (a saved page) lists every one with a ready-to-paste fix. Shown only when the check applied.
function authzFindingsHTML(data) {
  var az = data.authz_scan;
  if (!az || !az.applicable) return '';
  var crit = az.critical || 0, rev = az.review || 0, sc = az.scope || {};
  var h = '<div style="border:0.5px solid var(--bdr);border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px;font-size:13px">';
  h += '<div style="font-weight:600;margin-bottom:4px">Who can do what</div>';
  if (!crit && !rev) {
    var bits = [];
    if (sc.tables) bits.push(sc.tables + (sc.tables === 1 ? ' table' : ' tables'));
    if (sc.database_functions) bits.push(sc.database_functions + (sc.database_functions === 1 ? ' database action' : ' database actions'));
    if (sc.backend_functions) bits.push(sc.backend_functions + (sc.backend_functions === 1 ? ' backend function' : ' backend functions'));
    h += '<div><strong style="color:var(--gr)">\u2713 No obvious access problems found</strong></div>';
    if (bits.length) h += '<div style="color:var(--mut);font-size:12px;margin-top:4px">Read ' + esc(bits.join(', ')) + '.</div>';
  } else {
    var col = crit ? 'var(--rd,#E24B4A)' : 'var(--or,#EF9F27)';
    var head = crit
      ? crit + (crit === 1 ? ' serious access problem' : ' serious access problems') + ' found' + (rev ? ' \u00b7 ' + rev + ' more to check' : '')
      : rev + (rev === 1 ? ' place' : ' places') + ' to check';
    h += '<div><strong style="color:' + col + '">' + esc(head) + '</strong></div>';
    if (az.example) {
      h += '<div style="margin-top:6px"><strong>' + esc(az.example.title) + '</strong>';
      h += '<div style="color:var(--mut);font-size:12px;line-height:1.5;margin-top:2px">' + esc(az.example.plain) + ' <span style="font-family:monospace">' + esc(az.example.file) + '</span></div></div>';
    }
    h += '<div style="font-size:12px;color:var(--txt);margin-top:8px">The <a href="/deep-scan" style="color:var(--pu)">deep scan</a> lists every one with a ready-to-paste fix for your AI builder.</div>';
  }
  h += '<div style="color:var(--mut);font-size:11px;margin-top:6px">' + esc(az.scope_note || '') + '</div></div>';
  return h;
}

function osvFindingsHTML(data) {
  var osv = data.osv_scan;
  if (osv && osv.coverage && osv.coverage.scope === 'unavailable') {
    return '<div style="border:0.5px solid #EF9F27;background:#FEF9C3;border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px;font-size:13px"><strong>&#9888; The dependency check could not run this time</strong><div style="color:#92400E;font-size:12px;line-height:1.5;margin-top:6px">' + esc(osv.coverage.note || '') + '</div></div>';
  }
  if (!osv || !osv.packages_checked) return '';

  var h = '<div style="border:0.5px solid var(--bdr);border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px;font-size:13px">';
  var noun = osv.packages_checked === 1 ? 'dependency' : 'dependencies';
  // What was actually covered, in plain words (worked out on the server). "All" is only said when the
  // whole package list was read; older reports carry no coverage and make no claim of completeness.
  var cov = osv.coverage || {};
  var pk = osv.packages_checked + (osv.packages_checked === 1 ? ' package' : ' packages');
  var covSum = cov.summary || pk;
  var covNote = cov.note ? '<div style="color:#92400E;font-size:12px;line-height:1.5;margin-top:6px">' + esc(cov.note) + '</div>' : '';

  if (!osv.vulnerabilities_found) {
    h += '<div><strong style="color:var(--gr)">✓ ' + esc(cov.scope === 'full' ? 'All ' + pk + ' checked' : covSum + ' checked') + ' — none vulnerable</strong></div>';
    h += '<div style="color:var(--mut);font-size:12px;line-height:1.5;margin-top:6px">';
    h += (cov.scope === 'full' ? 'Every package in your project was checked' : 'These packages were checked') + ' against OSV.dev, a public database of known security vulnerabilities. None have a documented issue right now — worth re-checking occasionally, since new vulnerabilities get discovered in existing libraries over time.';
    h += '</div>' + covNote + '</div>';
    return h;
  }

  var vword = osv.vulnerabilities_found === 1 ? 'dependency has' : 'dependencies have';
  var col = osv.critical > 0 ? 'var(--rd,#E24B4A)' : 'var(--or,#EF9F27)';
  h += '<div><strong style="color:' + col + '">' + osv.vulnerabilities_found + ' ' + vword + ' known vulnerabilities</strong>';
  h += '<span style="color:var(--mut)"> &nbsp;·&nbsp; checked ' + esc(covSum) + ' against OSV.dev</span></div>';
  h += covNote;
  h += '<div style="color:var(--mut);font-size:12px;line-height:1.5;margin-top:6px">';
  h += osv.critical + ' serious, ' + osv.warnings + ' less severe. These are real, named, publicly documented issues in the exact library versions your app uses — the same kind of check tools like Snyk and GitHub\'s own security alerts run.';
  h += '</div>';
  h += '<div style="font-size:12px;color:var(--txt);margin-top:8px">Two ways to fix this: ask your AI builder to investigate using the free advice prompt below, or skip the investigation — the <a href="/deep-scan" style="color:var(--pu)">deep scan</a> hands you the exact package names, versions, and fixes already found.</div>';
  h += '</div>';
  return h;
}

// Findings from the deterministic scan. These are a different kind of thing from
// the layer findings: read directly out of the file, same answer every run, exact
// line number. Shown separately so the certain and the assessed are never blurred.
function verifiedFindingsHTML(data) {
  var scan = data.secret_scan;
  if (!scan || !scan.files_scanned) return '';
  var items = scan.findings || [];

  var h = '<div style="border:0.5px solid var(--bdr);border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px;font-size:13px">';

  if (!items.length) {
    h += '<div><strong style="color:var(--gr)">✓ No exposed keys or passwords found</strong></div>';
    h += '<div style="color:var(--mut);font-size:12px;line-height:1.5;margin-top:6px">';
    h += 'All ' + scan.files_scanned + ' files were read and checked for API keys, passwords, private keys and database logins written directly into the code. Nothing was found. This check is complete — it is not a sample.';
    h += '</div></div>';
    return h;
  }

  var word = items.length === 1 ? 'finding' : 'findings';
  h += '<div><strong style="color:var(--rd,#E24B4A)">' + items.length + ' verified ' + word + '</strong>';
  h += '<span style="color:var(--mut)"> &nbsp;·&nbsp; found by reading all ' + scan.files_scanned + ' of your files</span></div>';
  h += '<div style="color:var(--mut);font-size:12px;line-height:1.5;margin-top:4px">These are certain. Each one was read straight out of the file shown, so unlike the reviewed findings below, they will not change between runs.</div>';

  items.forEach(function(f) {
    var isCrit = f.severity === 'critical';
    var col = isCrit ? 'var(--rd,#E24B4A)' : (f.severity === 'warning' ? 'var(--or,#EF9F27)' : 'var(--mut)');
    h += '<div style="margin-top:10px;padding-top:10px;border-top:0.5px solid var(--bdr)">';
    h += '<div style="font-weight:600;color:' + col + '">' + esc(f.name) + '</div>';
    h += '<div style="font-family:monospace;font-size:12px;color:var(--mut);margin-top:2px">' + esc(f.file) + ' &middot; line ' + f.line + ' &middot; starts "' + esc(f.preview) + '"</div>';
    h += '<div style="margin-top:6px;line-height:1.5">' + esc(f.plain) + '</div>';
    if (f.action) {
      h += '<div style="margin-top:6px;line-height:1.5"><strong>What to do:</strong> ' + esc(f.action) + '</div>';
    }
    h += '</div>';
  });

  h += '</div>';
  return h;
}

function toggleFileList() {
  var el = document.getElementById('filelist');
  var btn = document.getElementById('filelist-toggle');
  if (!el) return;
  if (el.style.display === 'none') {
    el.style.display = 'block';
    if (btn) btn.textContent = 'Hide files';
  } else {
    el.style.display = 'none';
    if (btn) btn.textContent = 'Show files';
  }
}

function verdictBannerHTML(score, prevScore, crit) {
  var map = {
    A: ['#EAF3DE','#27500A','ti-circle-check','Production ready','No critical or warning findings — keep dependencies current as you add features.'],
    B: ['#EAF3DE','#27500A','ti-circle-check','Safe to launch','The realistic target for AI-built apps. See the score guide below for how to reach A.'],
    C: ['#FAEEDA','#633806','ti-alert-triangle','Needs work before going live','Address the critical findings below, then re-run to update the score.'],
    D: ['#FCEBEB','#A32D2D','ti-alert-circle','Not ready to launch','Fix the critical findings below before launching with real users.'],
    F: ['#FCEBEB','#A32D2D','ti-alert-circle','Not ready to launch','Several critical findings — fix these before launching with real users.']
  };
  var v = (map[score] || map.C).slice();
  if (crit === 0 && 'CDF'.indexOf(score) !== -1) v[4] = 'No critical findings, but the warnings below add up. Work through them, then re-run to update the score.';   // a grade from warnings alone
  var html = '<div class="prod-banner" style="background:' + v[0] + ';color:' + v[1] + '">';
  html += '<i class="ti ' + v[2] + '" style="font-size:26px"></i>';
  html += '<div style="flex:1"><div style="font-size:16px;font-weight:600;margin-bottom:2px">' + v[3] + '</div>';
  html += '<div style="font-size:13px;opacity:.85">' + v[4] + '</div></div>';
  if (prevScore && prevScore !== score) {
    var scores = ['F','D','C','B','A'];
    var prevIdx = scores.indexOf(prevScore);
    var currIdx = scores.indexOf(score);
    if (currIdx > prevIdx) {
      html += '<div style="background:#1D9E75;color:#fff;border-radius:20px;padding:4px 12px;font-size:13px;font-weight:600;white-space:nowrap">▲ ' + prevScore + ' → ' + score + ' Improved!</div>';
    } else if (currIdx < prevIdx) {
      html += '<div style="background:#E24B4A;color:#fff;border-radius:20px;padding:4px 12px;font-size:13px;font-weight:600;white-space:nowrap">▼ ' + prevScore + ' → ' + score + '</div>';
    }
  }
  html += '</div>';
  return html;
}

// ── Results page: grouped, collapsible sections (2026-10-10) ────────────────
function secHtml(id, title, meta, body, open) {
  return '<details class="sec" id="' + id + '"' + (open ? ' open' : '') + '><summary>' + esc(title) +
         '<span class="sec-meta" id="' + id + '-sum">' + esc(meta) + '</span></summary>' +
         '<div class="sec-body">' + body + '</div></details>';
}

function layersSummaryText(h, incomplete) {
  if (incomplete && incomplete.length) return (h.critical || 0) + ' critical · ' + (h.warnings || 0) + ' warnings · not checked: ' + incomplete.join(', ');
  return (h.critical || 0) + ' critical · ' + (h.warnings || 0) + ' warnings · ' + (h.passing || 0) + ' with no issues seen';
}

function checksSummaryText(data) {
  var parts = [];
  var read = data.files_read || 0, total = data.files_total || read;
  if (read) parts.push(read + (total && total !== read ? ' of ' + total : '') + ' files read');
  var sc = data.secret_scan;
  if (sc && typeof sc.files_scanned === 'number') {
    var n = (sc.critical || 0) + (sc.warnings || 0);
    parts.push(n ? n + ' possible exposed key' + (n !== 1 ? 's' : '') : 'no exposed keys');
  }
  var osv = data.osv_scan;
  if (osv && osv.packages_checked) {
    parts.push(osv.vulnerabilities_found
      ? osv.vulnerabilities_found + ' vulnerable package' + (osv.vulnerabilities_found !== 1 ? 's' : '')
      : osv.packages_checked + ((osv.coverage && (osv.coverage.scope === 'direct' || osv.coverage.scope === 'listed')) ? ' direct packages clean' : (osv.coverage && osv.coverage.scope === 'partial') ? ' packages clean (part of the project)' : ' packages clean'));
  }
  var az = data.authz_scan;
  if (az && az.applicable) {
    parts.push(az.critical ? az.critical + ' access problem' + (az.critical !== 1 ? 's' : '')
      : az.review ? az.review + ' to check' : 'no access problems');
  }
  return parts.join(' · ');
}

function incompleteBannerHTML(names) {
  return '<div class="prod-banner" style="background:#F1EFE8;color:#444441">' +
    '<i class="ti ti-alert-triangle" style="font-size:26px"></i>' +
    '<div style="flex:1"><div style="font-size:16px;font-weight:600;margin-bottom:2px">Analysis incomplete</div>' +
    '<div style="font-size:13px;opacity:.85">Verilay could not finish checking: ' + esc(names.join(', ')) +
    '. This is not a grade and does not mean those parts are fine. Run the analysis again.</div></div></div>';
}

// Open a group and bring it into view (used by the "Ask" button; optional input to focus).
function openSection(id, focusId) {
  var d = document.getElementById(id);
  if (!d) return;
  d.open = true;
  d.scrollIntoView({behavior: 'smooth', block: 'start'});
  if (focusId) setTimeout(function() { var el = document.getElementById(focusId); if (el && !el.disabled) el.focus(); }, 350);
}

function toggleAllSections(open) {
  document.querySelectorAll('details.sec').forEach(function(d) { d.open = open; });
}

// A layer group (e.g. Auth/Config/Database) failed or timed out: say so plainly and never let the page
// look like a clean pass on the strength of the layers that did arrive.
function layerFailed(evt, names) {
  window._incompleteLayers = (window._incompleteLayers || []).concat(names);
  var msg = (evt && typeof evt.data === 'string' && evt.data.trim()) ? evt.data
    : 'The ' + names.join(', ') + ' check could not be completed. Run the analysis again to see it.';
  showLayerError(msg);
  updateHealthDisplay();
}

// The "More" box under the fixes: one button per section; a button opens its section and closes the others. The share
// banner (with the directory card that sits next to it) is moved into "Share and IT pack" so its existing code keeps working.
function renderMoreBox(more, keepBase) {
  var box = document.getElementById('report-more');
  if (!box) return;
  var inner = box.querySelector('.more-box');
  if (keepBase && inner) {
    // Part 2 only adds its own sections. The report's sections stay as they are, because they are filled in after they
    // are drawn (the grade, the scan details, the app diagram). Redrawing them from the copy kept at the start put the
    // "your score appears once all layers are checked" note back under a finished report (28 Oct 2026, report 65976360e806).
    var baseIds = (window._moreBase || []).map(function(m) { return m[0]; });
    more.forEach(function(m) {
      var old = document.getElementById(m[0]);
      if (old && baseIds.indexOf(m[0]) !== -1) return;
      if (old && inner.contains(old)) old.outerHTML = m[2];
      else inner.insertAdjacentHTML('beforeend', m[2]);
    });
    var cnt = document.getElementById('more-count');
    if (cnt) cnt.textContent = '(' + inner.querySelectorAll('details.sec').length + ')';
    bindMoreToggles(box);
    return;
  }
  var banner = document.getElementById('share-banner'), rpt = document.getElementById('rpt');
  if (banner && rpt && box.contains(banner)) rpt.appendChild(banner);       // keep it alive while the box is redrawn
  var dir = document.getElementById('directory-card');
  if (dir && rpt && box.contains(dir)) rpt.appendChild(dir);
  // Just the folded sections, one line each (28 Oct 2026, Moses: the row of name buttons above them repeated the same
  // names). Opening one closes the others, so only one is open at a time.
  // 29 Oct 2026 (Moses: visitors may not notice "More"): a heading that says what is inside and how much, and a
  // coloured edge so it reads as part of the report, not page furniture.
  box.innerHTML = '<div class="more-box" style="background:var(--sur);border:0.5px solid var(--bdr);border-left:4px solid var(--pu);' +
    'border-radius:var(--r);padding:.85rem 1rem;margin:.85rem 0">' +
    '<div style="font-size:16px;font-weight:600;color:var(--put);margin-bottom:2px">More details <span id="more-count" ' +
    'style="font-weight:500;color:var(--mut);font-size:14px">(' + more.length + ')</span></div>' +
    '<div style="font-size:13px;color:var(--mut);margin-bottom:.4rem">Your grade explained, the checks we ran, how your app fits together and more. Tap one to open it.</div>' +
    more.map(function(m) { return m[2]; }).join('') + '</div>';
  var slot = document.getElementById('share-slot');
  if (slot && dir) slot.appendChild(dir);
  if (slot && banner) slot.appendChild(banner);
  bindMoreToggles(box);
}
// Opening one section of "More" closes the others. Each section is bound once.
function bindMoreToggles(box) {
  box.querySelectorAll('details.sec').forEach(function(d) {
    if (d._moreBound) return;
    d._moreBound = true;
    d.addEventListener('toggle', function() {
      if (!d.open) return;
      box.querySelectorAll('details.sec').forEach(function(o) { if (o !== d) o.open = false; });
      // 29 Oct 2026: do visitors open "More" at all, and which parts? Counted before deciding to move anything out of it.
      try { if (typeof plausible === 'function') plausible('More Section Open', {props: {section: d.id}}); } catch (e) {}
    });
  });
}

// "What's next" (26 Oct 2026): one line at the end of a finished Pro or deep report (Self Fix when there is something to
// fix, Monitoring when there is nothing serious), and a quiet footer on every report. Same rule as app.py whats_next_html.
function whatsNextHTML(data, h) {
  var kind = data.is_deep_scan ? 'deep' : (data.scan_tier === 'pro' ? 'pro' : 'free');
  var s = h && h.score, offer = null;
  if ((kind === 'pro' || kind === 'deep') && s) {
    if ((h.critical || 0) > 0 || 'CDF'.indexOf(s) !== -1) offer = 'fix';
    else if (s === 'A' || s === 'B') offer = 'monitor';
  }
  var line = '';
  if (offer === 'fix') {
    line = '<div class="whats-next" data-offer="fix" style="display:flex;gap:10px;align-items:flex-start;background:var(--pul);color:var(--put);' +
      'border-radius:10px;padding:.7rem .9rem;margin:.85rem 0;font-size:14px;line-height:1.5"><span style="font-size:18px;line-height:1.2">&#128295;</span>' +
      '<span><strong>Not sure how to fix these?</strong> A <strong>Verilay Self Fix session</strong> walks you through each fix with your AI builder, checks its replies, and rescans to confirm. Coming soon. <a href="/pricing?src=report#fix-interest" target="_blank" rel="noopener" ' +
      'style="color:var(--pu);font-weight:600;white-space:nowrap">Get early access &rarr;</a></span></div>';
  } else if (offer === 'monitor') {
    line = '<div class="whats-next" data-offer="monitor" style="display:flex;gap:10px;align-items:flex-start;background:#E1F5EE;color:#085041;' +
      'border-radius:10px;padding:.7rem .9rem;margin:.85rem 0;font-size:14px;line-height:1.5"><span style="font-size:18px;line-height:1.2">&#128737;</span>' +
      '<span><strong>Keep it that way.</strong> <strong>Monitoring</strong> re-checks your app on a schedule and emails you when something new turns up: a new package problem, an exposed key, or a grade change. Coming soon. <a href="/monitoring?src=report#form" target="_blank" rel="noopener" ' +
      'style="color:#1D9E75;font-weight:600;white-space:nowrap">Get early access &rarr;</a></span></div>';
  }
  return line + '<div class="options-footer" style="text-align:center;font-size:12px;color:var(--mut);margin:.85rem 0 .25rem">What else Verilay can do: ' +
    'Pro &middot; Self Fix sessions &middot; Monitoring &middot; <a href="/pricing?src=footer" target="_blank" rel="noopener" style="color:var(--pu);font-weight:600">' +
    'See all options &rarr;</a><br><a href="/newsletter" target="_blank" rel="noopener" style="color:var(--pu)">Get the monthly newsletter</a></div>';
}

// ── "Start here" (28 Oct 2026, Moses: everything at once felt like a cognitive load) ──────────────────────────────────
// The report now opens with three answers: how is my app doing (grade + one sentence), what should I do first (the most
// serious fix with its copy button), and the next step (the Pro strip, added under this card by showProTopBanner).
// Everything else is one tap away: the areas below, the other fixes folded, the extras in "More".
var _VERDICT_SHORT = {A: 'Ready for real users', B: 'Safe to launch', C: 'Needs some work before real users',
                      D: 'Not ready for real users yet', F: 'Not ready: several serious problems'};
var _GRADE_TONE = {A: ['#E1F5EE', '#085041'], B: ['#EFF6FF', '#1D4ED8'], C: ['#FAEEDA', '#633806'], D: ['#FCEBEB', '#A32D2D'], F: ['#FCEBEB', '#7F1D1D']};
function _whyGrade(score, crit, h) {
  if (score === 'B' && !crit && h && h.limited_coverage && !h.warnings)
    return 'Nothing serious was found in the files Verilay could read, but that was only a small part of your code, so the grade stops at B.';
  if (score === 'A') return 'No critical or warning findings in what Verilay read. Keep your packages up to date as you add features, and scan again after big changes.';
  if (score === 'B') return 'No critical problems. B is the realistic target for apps built with AI tools: safe to put in front of real users. Reaching A needs a developer-level review.';
  if (score === 'C') return crit ? 'There is at least one serious problem. Fix the one below first: on its own it often lifts the grade to a B, the realistic goal for apps built with AI tools.'
                                 : 'No critical problems, but several warnings add up. Work through them, starting with the one below, to reach a B.';
  return crit ? 'There are serious problems that could expose your users or your data. Fix them, starting with the one below, before inviting real users.'
              : 'Several problems add up to a low grade. Work through them, starting with the one below, before inviting real users.';
}
function _firstFix(data) {
  var list = (window._p2Fixes && window._p2Fixes.length) ? window._p2Fixes : ((data && data.top_fixes) || []);
  for (var i = 0; i < list.length; i++) {
    var f = list[i] || {};
    if (f.title && !/no critical fixes needed/i.test(f.title)) return f;
  }
  return null;
}
// Which AI builder made the app, from the AI's "built with" sentence. Only its opening words count (the sentence starts
// with the answer, e.g. "Lovable - the index.html has the badge"), so "Unknown - no markers (e.g., .lovable, .bolt)" is
// not read as Lovable (28 Oct 2026: Verilay's own repo was shown "Copy the fix prompt for Lovable").
function builderFromBuiltWith(text) {
  var lead = String(text || '').toLowerCase().split(/\s[\u2014\u2013-]\s|[(:;,]|\.(?=\s|$)/)[0];   // "v0.4", "Bolt.new" stay whole
  if (/\b(unknown|unclear|not|no|none|human|hand|custom)\b/.test(lead)) return '';
  if (/\blovable\b/.test(lead)) return 'Lovable';
  if (/\breplit\b/.test(lead)) return 'Replit';
  if (/\bbolt\b/.test(lead)) return 'Bolt';
  if (/\bv0(?:\.dev\b|(?![\w.]))/.test(lead)) return 'v0';     // "v0.dev" or "v0", not "v0.4 of a library"
  if (/\bcursor\b/.test(lead)) return 'Cursor';
  if (/\b(google )?ai studio\b/.test(lead)) return 'Google AI Studio';
  return '';
}
function _fixPrompt(f, data) {
  var tool = builderFromBuiltWith(data && data.built_with);
  var p = f.general_prompt || f.lovable_prompt || '';
  if (tool === 'Lovable' && f.lovable_prompt) p = f.lovable_prompt;
  else if (tool === 'Replit' && f.replit_prompt) p = f.replit_prompt;
  return [p, tool ? 'Copy the fix prompt for ' + tool : 'Copy the fix prompt for your AI builder'];
}
function startHereHTML(data, h, hasLayers, isPreview) {
  if (isPreview) return '';
  var head = '<div style="font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--mut)">Start here &middot; ' + esc(data.repo || 'your app') + '</div>';
  var box = 'background:var(--sur);border:1.5px solid var(--txt);border-radius:16px;padding:1rem 1.1rem;margin:0 0 10px';
  if (!hasLayers) {
    return '<div style="' + box + '">' + head + '<div style="display:flex;gap:10px;align-items:center;margin-top:.55rem;font-size:15px;color:var(--mut)">' +
      '<div style="width:18px;height:18px;border:2px solid var(--pul);border-top-color:var(--pu);border-radius:50%;animation:sp 1s linear infinite;flex-shrink:0"></div>' +
      'Checking your app&hellip; your grade and the first thing to fix appear here.</div></div>';
  }
  if (scanFullyIncomplete()) return '';            // the "could not finish" note below explains it
  // While a scan is still running, the grade is not shown: it was worked out from the first areas and could change
  // (Moses saw B turn into C). It appears once every area is in.
  var done = Object.keys(currentLayers || {}).length;
  if (window._scanStreaming && !window._analysisComplete && done < 6) {
    return '<div style="' + box + '">' + head + '<div style="display:flex;gap:10px;align-items:center;margin-top:.55rem;font-size:15px;color:var(--mut)">' +
      '<div style="width:18px;height:18px;border:2px solid var(--pul);border-top-color:var(--pu);border-radius:50%;animation:sp 1s linear infinite;flex-shrink:0"></div>' +
      '<span>Still checking: ' + done + ' of 6 areas done. Your grade and the first thing to fix appear here when all are in.</span></div></div>';
  }
  var s = h.score || '?', tone = _GRADE_TONE[s] || ['#F1EFE8', '#444441'];
  var crit = h.critical || 0, warn = h.warnings || 0;
  var html = '<div style="' + box + '">' + head +
    '<div style="display:flex;gap:14px;align-items:center;margin:.55rem 0 .15rem">' +
    '<div style="width:64px;height:64px;border-radius:16px;background:' + tone[0] + ';color:' + tone[1] + ';font-size:36px;font-weight:800;display:flex;' +
    'align-items:center;justify-content:center;flex-shrink:0">' + esc(s) + '</div><div style="min-width:0">' +
    '<div style="font-size:19px;font-weight:700;line-height:1.3">' + esc(_VERDICT_SHORT[s] || 'Your result') + '</div>' +
    '<div style="font-size:13px;color:var(--mut)">' + areasCheckedText() + ' areas checked &middot; ' + crit + ' critical &middot; ' + warn + ' warning' + (warn === 1 ? '' : 's') + '</div>' +
    '<a href="#" onclick="var t=document.getElementById(\'start-why\');t.style.display=t.style.display===\'block\'?\'none\':\'block\';return false;" ' +
    'style="font-size:13px;color:var(--pu);font-weight:600">Why this grade?</a></div></div>' +
    '<div id="start-why" style="display:none;font-size:13px;color:var(--mut);background:var(--bg);border-radius:8px;padding:.6rem .75rem;margin-top:.4rem;line-height:1.55">' +
    esc(_whyGrade(s, crit, h)) + ' <a href="#" onclick="openSection(\'sec-grade\');return false;" style="color:var(--pu)">More about your grade</a></div>';
  var f = _firstFix(data);
  if (f) {
    var pr = _fixPrompt(f, data);
    var _w = String(f.why_it_matters || ''), _m = _w.match(/^[^.!?]*[.!?]/);      // the first sentence (no look-behind: older Safari)
    var why = (_m ? _m[0] : _w).slice(0, 220);
    var sevRed = (f.severity || '') === 'critical';
    html += '<div style="background:' + (sevRed ? 'var(--rdl)' : 'var(--orl)') + ';border-radius:12px;padding:.85rem .95rem;margin-top:.9rem">' +
      '<div style="font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:' + (sevRed ? 'var(--rdt)' : 'var(--ort)') + '">Do this first</div>' +
      '<div style="font-size:16px;font-weight:700;margin:.15rem 0 .2rem;line-height:1.35">' + esc(f.title) + '</div>' +
      (why ? '<div style="font-size:13px;color:#444;line-height:1.5">' + esc(why) + '</div>' : '') +
      (pr[0] ? '<button type="button" id="start-copy" style="margin-top:.6rem;background:var(--pu);color:#fff;border:0;border-radius:10px;padding:9px 16px;' +
               'font-size:14px;font-weight:600;font-family:inherit;cursor:pointer">' + esc(pr[1]) + '</button>' +
               '<span id="start-copied" style="display:none;font-size:13px;color:var(--grt);margin-left:8px">&#10003; Copied. Paste it into your AI chat.</span>' : '') +
      '</div>';
    window._startPrompt = pr[0];
  } else if (s === 'A' || s === 'B') {
    html += '<div style="background:var(--grl);color:var(--grt);border-radius:12px;padding:.75rem .95rem;margin-top:.9rem;font-size:14px">' +
      '<strong>Nothing urgent to fix.</strong> Keep it that way: scan again after big changes.</div>';
  } else {
    html += '<div style="font-size:13px;color:var(--mut);margin-top:.8rem">Preparing the first thing to fix&hellip;</div>';
  }
  return html + '</div>';
}
function refreshStartHere() {
  var box = document.getElementById('start-here');
  if (!box || !currentReport) return;
  var h = currentReport.health || {};
  var has = Object.keys(currentLayers || {}).length > 0;
  box.innerHTML = startHereHTML(currentReport, h, has, !!currentReport.preview_only);
}
// The copy button in "Start here": the same safety reminder as the other fix prompts, then the rating nudge.
document.addEventListener('click', function(e) {
  var b = e.target && e.target.closest ? e.target.closest('#start-copy') : null;
  if (!b || !window._startPrompt) return;
  var ok = confirm('Before applying this advice:\n\n1. Paste it into your AI builder\n2. Read its response carefully\n' +
                   '3. Ask it to ADVISE first, not make changes yet\n4. Only apply changes it confirms are safe\n\nCopy the fix prompt?');
  if (!ok) return;
  navigator.clipboard.writeText(window._startPrompt).then(function() {
    var c = document.getElementById('start-copied'); if (c) c.style.display = 'inline';
    try { if (typeof plausible === 'function') plausible('Start Here Copy'); } catch (err) {}
    setTimeout(showRatingNudge, 2500);
  });
});
// A small count badge next to each area's name (the words are in its tooltip): red = critical, amber = warnings,
// green tick = no issues, grey dash = not checked. Compact so it fits the narrow area buttons on a phone.
function layerCountChip(layer) {
  if (!layer) return '';
  if (layer.status === 'not_checked') return '<span class="lchip" title="Not checked" style="background:#F1EFE8;color:#5F5E5A">&ndash;</span>';
  var fs = (layer.expert && layer.expert.findings) || layer.findings || [];
  var c = 0, w = 0;
  fs.forEach(function(x) { var s = (x && x.severity || '').toLowerCase(); if (s === 'critical') c++; else if (s === 'warning') w++; });
  if (c) return '<span class="lchip" title="' + c + ' critical' + (w ? ', ' + w + ' warning' + (w === 1 ? '' : 's') : '') + '" style="background:var(--rdl);color:var(--rdt)">' + c + '</span>';
  if (w) return '<span class="lchip" title="' + w + ' warning' + (w === 1 ? '' : 's') + '" style="background:var(--orl);color:var(--ort)">' + w + '</span>';
  return '<span class="lchip" title="No issues found" style="background:var(--grl);color:var(--grt)">&#10003;</span>';
}

// "Email me this report" (28 Oct 2026): keeps a free report for good by saving it to an account. The button waits
// for the report to be saved (savedReportId); the email's link signs them in and the report joins their account.
function emailReportHTML() {
  return '<div id="em-card" style="margin:.85rem 0;padding:1rem;background:var(--sur);border:1px solid var(--pu);border-radius:var(--r)">' +
    '<div style="font-size:16px;font-weight:600;color:var(--txt);margin-bottom:2px">&#9993;&#65039; Email me this report</div>' +
    '<div style="font-size:13px;color:var(--mut);margin-bottom:.6rem;line-height:1.55">Get the link in your inbox and keep this report. ' +
    'Free reports are deleted after 90 days unless you save them.</div>' +
    '<div style="display:flex;gap:8px;flex-wrap:wrap"><input id="em-email" type="email" maxlength="254" autocomplete="email" ' +
    'placeholder="you@example.com" aria-label="Your email" style="flex:1;min-width:180px;border:0.5px solid var(--bdr);border-radius:6px;' +
    'padding:8px 10px;font-size:14px;font-family:inherit;background:var(--bg);color:var(--txt)">' +
    '<button type="button" id="em-go" onclick="emailReport()" style="background:var(--pu);color:#fff;border:0;border-radius:6px;' +
    'padding:8px 16px;font-size:14px;font-weight:600;font-family:inherit;cursor:pointer">Email it to me</button></div>' +
    '<label style="display:flex;gap:8px;align-items:flex-start;font-size:13px;color:var(--mut);margin-top:.6rem">' +
    '<input type="checkbox" id="em-news" style="margin-top:3px"> Also send me the monthly Verilay newsletter (tips for AI-built apps). Optional.</label>' +
    '<div style="font-size:12px;color:var(--mut);margin-top:.5rem">No password needed. Your next free scans are saved too, so you can compare them later.</div>' +
    '<div id="em-status" style="font-size:13px;color:var(--red, #A32D2D);margin-top:.4rem"></div></div>';
}
function emailReport() {
  var input = document.getElementById('em-email'), btn = document.getElementById('em-go'), st = document.getElementById('em-status');
  if (!input || !btn || btn.disabled) return;
  var em = (input.value || '').trim();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) { st.textContent = 'Please enter your email address.'; return; }
  if (!savedReportId) { st.textContent = 'Your report is still being saved. Try again in a moment.'; return; }
  btn.disabled = true; btn.textContent = 'Sending...'; st.textContent = '';
  fetch('/report/' + savedReportId + '/email-me', {method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Report-Token': reportToken(savedReportId)},
    body: JSON.stringify({email: em, newsletter: !!(document.getElementById('em-news') || {}).checked})})
    .then(function(r) { return r.json(); })
    .then(function(r) {
      if (r.ok) {
        try { if (typeof plausible === 'function') plausible('Email Report Sent'); } catch (e) {}
        var card = document.getElementById('em-card');
        card.style.background = '#E1F5EE'; card.style.borderColor = '#9fe1cb';
        card.innerHTML = '<div style="font-size:16px;font-weight:600;color:#085041;margin-bottom:3px">&#10003; ' +
          (r.saved ? 'Sent' : 'Check your inbox') + '</div><div style="font-size:13px;color:#085041;line-height:1.55">' +
          esc(r.message || 'Sent.') + '</div>';
        return;
      }
      st.textContent = r.error || 'That could not be sent. Please try again.';
      btn.disabled = false; btn.textContent = 'Email it to me';
    })
    .catch(function() { st.textContent = 'That could not be sent. Please try again.'; btn.disabled = false; btn.textContent = 'Email it to me'; });
}

// Suggested questions for "Ask Verilay about your report", fitted to the result.
function askChipsHTML(data, h) {
  var qs;
  h = h || {};
  if (data && data.preview_only) qs = ['Why should I scan my code instead?', 'What did this check look at?', 'Is my site set up safely?'];
  else if ((h.critical || 0) > 0) qs = ['What should I fix first?', 'Explain the critical issue simply', 'Is my app safe to launch?'];
  else if ((h.warnings || 0) > 0) qs = ['What should I fix first?', 'What do the warnings mean for me?', 'Is my app safe to launch?'];
  else qs = ['Is my app safe to launch?', 'How do I keep it this way?', 'What did Verilay check?'];
  return qs.map(function(q) {
    return '<button type="button" class="ask-chip" onclick="askChip(this.textContent)" style="border:0.5px solid var(--pu);background:var(--sur);' +
      'color:var(--put);border-radius:20px;padding:5px 12px;font-size:13px;font-family:inherit;cursor:pointer">' + esc(q) + '</button>';
  }).join('');
}
function refreshAskChips(h) {
  var box = document.getElementById('report-ask-chips');
  if (box && currentReport) box.innerHTML = askChipsHTML(currentReport, h || currentReport.health || {});
}
function askChip(q) {
  var input = document.getElementById('report-ask-input'), btn = document.getElementById('report-ask-btn');
  if (!input || !btn) return;
  if (btn.disabled && !savedReportId) {           // the report is not saved yet: say so instead of doing nothing
    var hint = document.getElementById('report-ask-hint'); if (hint) hint.style.display = 'block';
    return;
  }
  input.value = q;
  try { if (typeof plausible === 'function') plausible('Report Ask Chip'); } catch (e) {}
  askAboutReport();
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
  // When the deep-analysis layers are present, derive the score and counts from the
  // actual findings (same rubric as the server) so the header always matches the layers.
  // When they aren't yet (live step-1 view), leave h as-is — the cards will show a
  // "calculating" state until the layers arrive and updateHealthDisplay() fills them in.
  var hasLayers = !!(data.layers && data.layers.length);
  if (hasLayers) { h = healthFromLayers(data.layers, data); }
  var isPreview = !!data.preview_only;
  var pr = data.prod_ready || {};


  var html = tierBandHTML(data);

  if (isSurf) {
    html += '<div style="background:var(--orl);border-radius:var(--r);padding:.85rem 1rem;margin-bottom:10px;font-size:13px;color:var(--ort)"><strong>Surface scan only.</strong> Use GitHub or ZIP for a full analysis.</div>';
  }

  html += '<div id="start-here">' + startHereHTML(data, h, hasLayers, isPreview) + '</div>';
  html += '<div id="verdict-banner"></div>';     // only the "could not finish" / "not checked" notes now (updateHealthDisplay)

  // Static site recommendation: shown under "Checks we ran" (report tidy-up, 25 Oct 2026), not at the top.
  var staticHtml = '';
  var pr = data.prod_ready || {};
  if (pr.static_recommendation === 'yes' || pr.static_recommendation === 'partial') {
    staticHtml += '<div style="background:#EFF6FF;border:0.5px solid #3B82F6;border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px;display:flex;align-items:flex-start;gap:10px">';
    staticHtml += '<i class="ti ti-topology-star" style="color:#3B82F6;font-size:16px;margin-top:1px;flex-shrink:0"></i>';
    staticHtml += '<div>';
    staticHtml += '<div style="font-size:14px;font-weight:600;color:#1D4ED8;margin-bottom:2px">💡 Could this be a static site?</div>';
    if (pr.static_recommendation === 'yes') {
      staticHtml += '<div style="font-size:13px;color:#1D4ED8;line-height:1.55">' + esc(pr.static_reason || 'This app may not need a database or server — it could be simpler and cheaper to host as a static site on Netlify or Vercel for free.') + '</div>';
    } else {
      staticHtml += '<div style="font-size:13px;color:#1D4ED8;line-height:1.55">' + esc(pr.static_reason || 'Parts of this app could potentially be simplified. A static approach would reduce complexity and security risk.') + '</div>';
    }
    staticHtml += '</div></div>';
  }

  // (Scope/limitations notice consolidated into the files-coverage block below.)

  // Ask section — the report-grounded inline box (in-app, this repo's real
  // data) plus open-in-Claude (for a longer conversation with full code
  // access). The general Ask Verilay entry points (chips + "Open Ask
  // Verilay" link) used to live here too, but Moses found having 4
  // different "ask something" affordances in one card confusing -- general
  // Ask Verilay still exists as its own separate page/nav link, just not
  // duplicated inside every report anymore.
  var askStart = html.length;
  // 28 Oct 2026 (Moses liked the compare page's Ask): a visible card right after the fix prompts, with suggested
  // questions to tap; it is no longer folded inside "More".
  html += '<div style="margin:.85rem 0;padding:1rem;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r)">';
  html += '<div style="font-size:16px;font-weight:600;color:var(--txt);margin-bottom:2px">&#128172; Ask Verilay about your report</div>';
  html += '<div style="font-size:13px;color:var(--mut);margin-bottom:.6rem;line-height:1.55">Plain-English answers about your results. Tap a question or type your own.</div>';
  html += '<div id="report-ask-chips" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:.6rem">' + askChipsHTML(data, h) + '</div>';
  html += '<div id="report-ask-hint" style="display:none;font-size:12px;color:var(--mut);margin-bottom:.4rem">Your report is still being saved; you can ask in a moment.</div>';
  // Report-grounded inline box -- disabled until the 'saved' SSE event sets
  // savedReportId (this card renders on step1, well before the report is
  // actually saved). See the 'saved' case in handleStreamEvent for the
  // enable step.
  html += '<div style="display:flex;gap:8px;margin-bottom:.6rem">';
  html += '<input id="report-ask-input" type="text" placeholder="Finishing your report — you can ask in a moment..." disabled ' +
          'onkeypress="if(event.key===\'Enter\')askAboutReport()" ' +
          'style="flex:1;min-width:0;border:0.5px solid var(--pu);border-radius:20px;padding:8px 14px;font-size:13px;font-family:inherit;background:var(--bg);color:var(--txt)" />';
  html += '<button id="report-ask-btn" onclick="askAboutReport()" disabled style="font-size:13px;padding:7px 16px;border-radius:20px;' +
          'background:var(--pu);color:#fff;border:none;cursor:not-allowed;white-space:nowrap;font-weight:500;opacity:.5">Ask</button>';
  html += '</div>';
  html += '<div id="report-ask-thread" style="display:flex;flex-direction:column;gap:8px;margin-bottom:.6rem"></div>';
  html += '<button onclick="askAIAboutReport()" style="font-size:13px;padding:7px 16px;border-radius:20px;background:var(--pu);color:#fff;border:none;cursor:pointer;white-space:nowrap;font-weight:500">Open Claude with my findings &rarr;</button>';
  html += '<span style="font-size:12px;color:var(--put);opacity:.7;margin-left:8px">Free Claude.ai account &mdash; digs into your specific code</span>';
  html += '</div>';
  var askHtml = html.slice(askStart);    // shown in its own card under the fixes (#report-ask), not in "More"
  html = html.slice(0, askStart);

  var pills = (data.stack||[]).map(function(s) {
    var c = catColors(s.category);
    return '<span class="pill" style="background:' + c[0] + ';color:' + c[1] + '">' + esc(s.name||'') + ' ' + esc(s.version||'') + '</span>';
  }).join('');

  var detailsStart = html.length;
  html += '<div class="rh">';
  html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">';
  html += '<div style="font-size:16px;font-weight:600">' + esc(data.repo||'') + '</div>';
  html += '<span style="font-size:12px;background:var(--pu);color:#fff;border-radius:10px;padding:2px 8px;font-weight:600">Current</span>';
  html += '</div>';
  html += '<div style="font-size:13px;color:var(--mut);margin-bottom:.65rem">' + esc(data.built_with||'') + '  .  ' + (data.files_read||0) + ' files  .  ' + (data.generated_at||'') + '</div>';
  html += '<div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:.65rem">' + pills + '</div>';
  html += '<div class="hg" id="health-grid">' + healthCardsHTML(h, hasLayers, isPreview) + '</div></div>';

  var detailsHtml = html.slice(detailsStart);          // repo, stack and the numbers: in "More" (Scan details)
  html = html.slice(0, detailsStart);
  var gradeHtml = '<div id="score-banner">' + scoreBannerHTML(h.score, hasLayers, isPreview, h.critical) + '</div>';
  if (isPreview) html += detailsHtml + gradeHtml;      // a live-address preview has no "Start here": keep its header in place
  var topHtml = html;
  html = '';

  var diagramHtml = '<div id="architecture-diagram-section">' + architectureDiagramHTML(data) + '</div>';

  var checksHtml = staticHtml + filesCoverageHTML(data) + fileBreakdownHTML(data);
  var discoveryInner = window._discoveryHtml || discoveryTeaserHTML(data);

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
      '<span style="flex:1">' + esc(l.name) + '</span>' + layerCountChip(l) +
      '<div class="ldot" style="background:' + (sdot[l.status]||sdot.passing) + '"></div>' +
      '</button>';
  }).join('');

  html += '<div class="panel on" id="p-layers">';
  html += '<div class="ll">';
  html += '<div class="lnav" id="layer-nav">';
  if (!isPreview) {
    html += '<div id="layers-loading" style="font-size:12px;color:var(--mut);padding:.5rem .25rem;display:flex;align-items:center;gap:6px">';
    html += '<div style="width:14px;height:14px;border:2px solid var(--pul);border-top-color:var(--pu);border-radius:50%;animation:sp 1s linear infinite;flex-shrink:0"></div>';
    html += 'Loading layers...</div>';
  }
  html += lbtns;
  html += '</div>';
  html += '<div class="ca">';
  html += '<div id="mode-toggle" class="mt" style="display:none">';
  html += '<span style="font-size:12px;color:var(--mut);align-self:center;margin-right:2px">View:</span>';
  html += '<button class="mb on" data-mode="expert">Expert</button>';
  html += '<button class="mb" data-mode="learner">Learner</button>';
  html += '<span style="flex-basis:100%;font-size:12px;color:var(--mut);line-height:1.4;margin-top:1px">New to this? <strong style="font-weight:600">Learner</strong> explains everything in plain English &mdash; no jargon.</span>';
  html += '</div>';
  // Only show spinner if no layers loaded yet
  var hasLayers = data.layers && data.layers.length > 0;
  html += '<div id="layer-content" style="padding:.75rem 0">';
  if (isPreview) {
    html += '<div style="font-size:13px;color:var(--mut);line-height:1.5">No layer-by-layer analysis for a URL preview. Scan your GitHub repo or upload a ZIP to get the full breakdown.</div>';
  } else if (!hasLayers) {
    html += '<div style="font-size:13px;color:var(--mut);display:flex;align-items:center;gap:8px">';
    html += '<div style="width:16px;height:16px;border:2px solid var(--pul);border-top-color:var(--pu);border-radius:50%;animation:sp 1s linear infinite;flex-shrink:0"></div>';
    html += 'Analysing your codebase - layers will appear shortly...</div>';
    html += '</div>';
  }
  html += '</div></div></div>';

  var scards = (data.stack||[]).map(function(s) {
    var c = catColors(s.category);
    return '<div class="sc"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:3px"><span style="font-size:13px;font-weight:500">' + esc(s.name||'') + '</span><span class="pill" style="font-size:12px;background:' + c[0] + ';color:' + c[1] + '">' + esc(s.category||'') + '</span></div><div style="font-size:12px;color:var(--mut);margin-bottom:2px">v' + esc(s.version||'?') + '</div><div style="font-size:12px;color:var(--mut);line-height:1.4">' + esc(s.plain_english||'') + '</div></div>';
  }).join('');
  html += '<div class="panel" id="p-stack"><div class="sg">' + scards + '</div></div>';

  var layersHtml = '<div id="layer-errors">' + layerErrorsHTML() + '</div>' + html;
  var incomplete = window._incompleteLayers || [];
  // Report tidy-up (25 Oct 2026): the page keeps what someone came for (the verdict above, the areas here, the fix
  // prompts below) and moves everything else into one "More" box under the fixes. Same sections, same ids.
  var sections = secHtml('sec-layers', 'What we found, by area', isPreview ? 'Needs your code (GitHub or ZIP)' : (hasLayers ? layersSummaryText(h, incomplete) : 'Analysing…'), layersHtml, !isPreview);
  if (isPreview && data.live_view) sections = secHtml('sec-live', 'About this live-site preview', 'What it saw, and tests to try', liveCheckHTML(data), true) + sections;
  var more = [];
  if (checksHtml) more.push(['sec-checks', 'Checks we ran', secHtml('sec-checks', 'Checks we ran', checksSummaryText(data), checksHtml, false)]);
  if (discoveryInner) more.push(['sec-similar', 'Similar apps', secHtml('sec-similar', 'Similar open-source projects', window._discoverySum || 'See what already exists',
                                          '<div id="discovery-slot">' + discoveryInner + '</div>', false)]);
  more.push(['sec-diagram', 'How your app fits together', secHtml('sec-diagram', 'How your app fits together', 'A map of the parts', diagramHtml, false)]);
  var askBox = document.getElementById('report-ask');
  if (askBox) askBox.innerHTML = askHtml;
  var emBox = document.getElementById('report-email');
  if (emBox) emBox.innerHTML = data.private ? '' : emailReportHTML();
  if (!isPreview) {
    more.unshift(['sec-grade', 'About your grade', secHtml('sec-grade', 'About your grade', 'What the grade means and how to reach the next one', gradeHtml, false)]);
    more.unshift(['sec-details', 'Scan details', secHtml('sec-details', 'Scan details', 'What was scanned, the tech stack and the numbers', detailsHtml, false)]);
  }
  more.push(['sec-share', 'Share and IT pack', secHtml('sec-share', 'Share and IT pack', 'Share link, README badge, app directory, IT Review Pack',
    '<div id="share-slot"></div><div style="font-size:13px;margin-top:.4rem"><a href="#" onclick="var b=document.getElementById(\'btn-it-review\');if(b)b.click();return false;" style="color:var(--pu);font-weight:600">Open the IT Review Pack</a> &middot; a printable checklist for IT teams approving this app</div>', false)]);
  document.getElementById('report-content').innerHTML = topHtml;
  document.getElementById('report-sections').innerHTML = sections;
  window._moreBase = more;
  renderMoreBox(more.concat(window._moreExtra || []));
  var nextBox = document.getElementById('report-next');
  if (nextBox) nextBox.innerHTML = (!isPreview && hasLayers && !scanFullyIncomplete()) ? whatsNextHTML(data, h) : '';
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
    html += '<div style="font-size:13px;color:var(--mut);margin-bottom:.75rem">' + esc(ex.summary||'') + '</div>';
    (ex.findings || []).forEach(function(f, fi) {
      html += '<div class="finding" style="' + sevStyle(f.severity) + '">';
      html += '<i class="ti ' + sevIcon(f.severity) + '" style="font-size:16px;flex-shrink:0;margin-top:1px"></i>';
      html += '<div><div style="font-weight:500;margin-bottom:2px">' + esc(f.title||'') + '</div>';
      html += '<div>' + esc(f.detail||'') + (f.file ? ' <code style="font-size:12px;opacity:.7">' + esc(f.file) + '</code>' : '') + '</div>';
      if (f.why_it_matters) html += '<div style="font-size:12px;margin-top:4px;opacity:.85"><strong>Why it matters:</strong> ' + esc(f.why_it_matters) + '</div>';
      // Add manual verification note for verify_jwt findings
      if (f.title && f.title.toLowerCase().indexOf('jwt') > -1) {
        html += '<div style="font-size:12px;margin-top:6px;padding:6px 8px;background:#FEF9C3;border-radius:6px;color:#854D0E">';
        html += '<strong>⚠️ Needs manual check:</strong> If your edge functions contain <code>getUser()</code> or <code>getClaims()</code> calls, this finding may not apply. ';
        html += 'Ask your AI builder: <em>"Do my edge functions validate auth in-code?"</em>';
        html += '</div>';
      }
      // Verify button for critical/warning findings
      if (f.severity === 'critical' || f.severity === 'warning') {
        var fKey = (activeLayer + '_' + fi).replace(/[^a-z0-9]/gi, '_').toLowerCase();
        var isVerified = currentVerifications && currentVerifications[fKey];
        if (isVerified) {
          html += '<div style="margin-top:8px;padding:6px 10px;background:#F0FDF4;border:0.5px solid #22C55E;border-radius:6px;font-size:12px;color:#166534">';
          html += '<strong>✅ Verified by AI builder</strong>';
          if (isVerified.verdict === 'false_positive') html += ' — confirmed not an issue';
          if (isVerified.verdict === 'fixed') html += ' — confirmed fixed';
          if (isVerified.builder_response) html += '<div style="margin-top:3px;opacity:.8;font-size:12px">' + esc(isVerified.builder_response.substring(0,120)) + (isVerified.builder_response.length > 120 ? '...' : '') + '</div>';
          html += '</div>';
        } else {
          html += '<div style="margin-top:8px">';
          var btnDisabled = !window._analysisComplete ? 'opacity:.4;cursor:not-allowed' : 'cursor:pointer';
          var btnClick = !window._analysisComplete ? '' : 'onclick="showVerifyPanel(\''+fKey+'\', this)"';
          var btnTitle = !window._analysisComplete ? 'title="Wait for full analysis to complete"' : '';
          html += '<button '+btnClick+' '+btnTitle+' style="font-size:12px;padding:4px 10px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);'+btnDisabled+'">✓ Mark as verified</button>';
          html += '<div id="verify-panel-'+fKey+'" style="display:none;margin-top:8px;background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.75rem">';
          html += '<div style="font-size:13px;font-weight:600;margin-bottom:4px">Paste your AI builder response:</div>';
          html += '<div style="font-size:12px;color:var(--mut);margin-bottom:6px">Take this finding to Lovable or Replit and ask them to verify it. Paste their response here.</div>';
          html += '<textarea id="verify-text-'+fKey+'" placeholder="Paste Lovable or Replit response here..." style="width:100%;height:70px;font-size:12px;padding:6px;border:0.5px solid var(--bdr);border-radius:6px;background:var(--bg);color:var(--txt);resize:vertical;box-sizing:border-box"></textarea>';
          html += '<div style="display:flex;gap:6px;margin-top:6px;flex-wrap:wrap">';
          html += '<button onclick="submitVerification(\''+fKey+'\', \'false_positive\')" style="font-size:12px;padding:4px 12px;border-radius:20px;background:#EFF6FF;color:#1D4ED8;border:0.5px solid #93C5FD;cursor:pointer">Already handled</button>';
          html += '<button onclick="submitVerification(\''+fKey+'\', \'fixed\')" style="font-size:12px;padding:4px 12px;border-radius:20px;background:#F0FDF4;color:#166534;border:0.5px solid #86EFAC;cursor:pointer">Fixed it</button>';
          html += '<button onclick="submitVerification(\''+fKey+'\', \'verified\')" style="font-size:12px;padding:4px 12px;border-radius:20px;background:var(--pul);color:var(--put);border:0.5px solid var(--pu);cursor:pointer">Verified — real issue</button>';
          html += '</div></div></div>';
        }
      }
      html += '</div></div>';
    });
  } else if (activeMode === 'learner') {
    var lrn = layer.learner || {};
    html += '<div class="learner-label"><i class="ti ti-school" style="font-size:12px"></i> Learner mode</div>';
    if (lrn.analogy) html += '<div class="analogy"><i class="ti ti-bulb" style="margin-right:5px"></i><strong>Think of it like this:</strong> ' + esc(lrn.analogy) + '</div>';
    html += '<div class="lc"><div class="lc-title">What is ' + esc(layer.name) + '?</div><div class="lc-body">' + esc(lrn.what_is_it||'') + '</div></div>';
    html += '<div class="lc"><div class="lc-title">In your app specifically</div><div class="lc-body">' + esc(lrn.what_it_does_in_your_app||'') + '</div></div>';
    if (lrn.how_it_connects) html += '<div class="lc"><div class="lc-title">How it connects to other layers</div><div class="lc-body">' + esc(lrn.how_it_connects) + '</div></div>';
    if (lrn.key_concept) html += '<div style="background:var(--pul);border-radius:8px;padding:.65rem .85rem;margin-bottom:8px;font-size:13px;color:var(--put)"><strong>Key concept:</strong> ' + esc(lrn.key_concept) + '</div>';
    (lrn.findings_plain || []).forEach(function(f) {
      html += '<div class="finding" style="' + sevStyle(f.severity) + '">';
      html += '<i class="ti ' + sevIcon(f.severity) + '" style="font-size:16px;flex-shrink:0;margin-top:1px"></i>';
      html += '<div><div style="font-weight:500;margin-bottom:2px">' + esc(f.plain_title||'') + '</div>';
      html += '<div>' + esc(f.plain_detail||'') + '</div>';
      if (f.real_world_impact && (f.severity === 'critical' || f.severity === 'warning')) {
        var riskAccent = f.severity === 'critical' ? '#E24B4A' : '#EF9F27';
        var riskBg = f.severity === 'critical' ? '#FDECEC' : '#FFF4E5';
        var riskTx = f.severity === 'critical' ? '#8a2a29' : '#7a4a00';
        html += '<div style="margin-top:6px;padding:8px 11px;background:' + riskBg + ';border-left:3px solid ' + riskAccent + ';border-radius:6px;font-size:13px;color:' + riskTx + ';line-height:1.5"><strong>&#9888;&#65039; What could go wrong:</strong> ' + esc(f.real_world_impact) + '</div>';
      } else if (f.real_world_impact) {
        html += '<div style="font-size:12px;margin-top:4px;font-style:italic">' + esc(f.real_world_impact) + '</div>';
      }
      if (f.action) html += '<div style="margin-top:5px;font-size:12px;font-weight:500">Action: ' + esc(f.action) + '</div>';
      // Learner mode — understand only, action happens in Expert mode
      if (f.severity === 'critical' || f.severity === 'warning') {
        html += '<div style="margin-top:10px;padding:8px 10px;background:var(--pul);border:0.5px solid var(--pu);border-radius:8px;font-size:12px;color:var(--put);line-height:1.55">';
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
      html += '<button id="quiz-toggle" style="font-size:13px;font-weight:500;padding:5px 14px;border-radius:20px;border:0.5px solid var(--pu);background:transparent;color:var(--put);cursor:pointer;display:flex;align-items:center;gap:5px">';
      html += '<i class="ti ti-brain" style="font-size:14px"></i> Test your understanding (optional quiz)';
      html += '</button>';
      html += '<div id="quiz-content" style="display:none;margin-top:.65rem">';
      quiz.forEach(function(q, i) {
        html += '<div class="qcard" style="margin-bottom:7px"><div style="font-size:13px;font-weight:500;margin-bottom:.5rem">' + esc(q.question||'') + '</div>';
        var hasAnswer = q.answer && q.answer.trim().length > 0;
        html += '<button id="qbtn-' + i + '" style="font-size:12px;padding:4px 12px;border-radius:20px;border:0.5px solid var(--put);background:transparent;color:var(--put);cursor:pointer">' + (hasAnswer ? 'Reveal answer' : 'No answer available') + '</button>';
        html += '<div id="qans-' + i + '" style="display:none;margin-top:.5rem;font-size:13px;color:var(--put);line-height:1.45"><strong>' + esc(q.answer || 'No answer provided for this layer yet.') + '</strong>';
        if (q.why) html += '<div style="font-size:12px;opacity:.8;margin-top:3px">' + esc(q.why) + '</div>';
        html += '</div></div>';
      });
      html += '</div></div>';
    }
  }

  var layerContentEl = document.getElementById('layer-content');
  layerContentEl.style.opacity = '0';
  layerContentEl.innerHTML = html;
  requestAnimationFrame(function() {
    layerContentEl.style.transition = 'opacity .25s ease';
    layerContentEl.style.opacity = '1';
  });

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
  startP2Trickle();

  try {
    var h = currentReport ? (currentReport.health||{}) : {};
    // Don't run Part 2 if app is already production ready
    if (h.score === 'A' && h.critical === 0) {
      stopP2Trickle();
      document.getElementById('p2-loading').style.display = 'none';
      document.getElementById('p2-results').innerHTML = `
        <div style="background:var(--grl);border:0.5px solid var(--grt);border-radius:var(--r);padding:1.25rem 1.5rem;margin-bottom:1rem">
          <div style="font-size:18px;font-weight:700;color:var(--grt);margin-bottom:.5rem">🎉 Score A — Production Ready!</div>
          <div style="font-size:14px;color:var(--grt);line-height:1.6">Your app passed all critical checks. This is the best possible result — it means no major security holes were found and your app appears safe to share with real users.</div>
        </div>
        <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1.25rem 1.5rem;margin-bottom:1rem">
          <div style="font-size:14px;font-weight:600;margin-bottom:.75rem">💡 What Score A actually means</div>
          <div style="font-size:14px;color:var(--mut);line-height:1.7">
            Think of it like a building inspection. Score A means the inspector found no structural problems, the electrics are safe, and it's ready for people to move in.<br><br>
            It does <strong>not</strong> mean the app is perfect — just that the most important safety checks passed. Like a new car passing its roadworthy test — it's safe to drive, but you still need to maintain it over time.
          </div>
        </div>
        <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1.25rem 1.5rem;margin-bottom:1rem">
          <div style="font-size:14px;font-weight:600;margin-bottom:.75rem">🔍 What Verilay checked to give this score</div>
          <ul style="font-size:14px;color:var(--mut);line-height:1.9;padding-left:1.25rem">
            <li><strong>Auth layer</strong> — are logins and sessions properly secured?</li>
            <li><strong>Config layer</strong> — are secrets and API keys properly hidden?</li>
            <li><strong>Database layer</strong> — is user data protected with proper access rules?</li>
            <li><strong>API layer</strong> — are your endpoints protected from abuse?</li>
            <li><strong>Frontend layer</strong> — is sensitive data hidden from the browser?</li>
            <li><strong>Libraries layer</strong> — are your dependencies safe and up to date?</li>
          </ul>
        </div>
        <div style="background:var(--pul);border:0.5px solid var(--pu);border-radius:var(--r);padding:1.25rem 1.5rem;margin-bottom:1rem">
          <div style="font-size:14px;font-weight:600;color:var(--put);margin-bottom:.75rem">📚 Keep learning — what to do next</div>
          <div style="font-size:14px;color:var(--put);line-height:1.7">
            Your app scored A today but apps change as you add features. Good habits to build:<br><br>
            <strong>Re-run Verilay</strong> every time you add a new login method, payment system, or database table.<br>
            <strong>Check your Supabase dashboard</strong> regularly — make sure Row Level Security is on for every new table you create.<br>
            <strong>Never commit .env files</strong> to GitHub — your API keys should only live in your hosting platform's environment variables.
          </div>
        </div>
        <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1.25rem 1.5rem">
          <div style="font-size:14px;font-weight:600;margin-bottom:.75rem">🚀 Ready to go live?</div>
          <div style="font-size:14px;color:var(--mut);line-height:1.7">
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
    // Real finding titles per layer, not just layer status — status alone gave
    // step4's Claude call nothing concrete to write specific fix prompts about,
    // so every report produced the same one generic "check your dependencies"
    // fix regardless of what was actually found. Libraries is the exception:
    // its finding text can include OSV-teaser wording, but never leak package
    // names/CVE ids here — Part 2 is free-tier, and free tier only ever gets
    // the count+severity split (Decision 6). Layer findings from Auth/Config/
    // Database/API/Frontend are safe to pass through verbatim since the free
    // report already shows them in full, nothing new is exposed.
    findings += 'Findings by layer:\n';
    Object.keys(currentLayers).forEach(function(name) {
      var layer = currentLayers[name];
      if (name === 'Libraries') {
        var osv = currentReport ? currentReport.osv_scan : null;
        if (osv && osv.vulnerabilities_found) {
          findings += '- Libraries ['+layer.status+']: '+osv.vulnerabilities_found+' dependencies have known vulnerabilities ('+
            osv.critical+' serious, '+osv.warnings+' less severe), checked '+((osv.coverage && osv.coverage.summary) ? osv.coverage.summary : osv.packages_checked+' packages')+' against OSV.dev. '+
            'Exact package names and fixed versions are not shown above — do not invent them.\n';
        } else {
          findings += '- Libraries ['+layer.status+']: no known dependency vulnerabilities.\n';
        }
        return;
      }
      var layerFindings = ((layer.expert||{}).findings || []).filter(function(f) {
        return f.title && f.title !== 'No issues found';
      });
      if (!layerFindings.length) {
        findings += '- '+name+': no issues found.\n';
      } else {
        layerFindings.slice(0,5).forEach(function(f) {
          findings += '- '+name+' ['+(f.severity||layer.status)+']: '+f.title+(f.detail ? ' — '+f.detail : '')+'\n';
        });
      }
    });
    var resp = await fetch('/analyse-step4', {
      method: 'POST',
      headers: reportHeaders(savedReportId, {'Content-Type': 'application/json'}),
      body: JSON.stringify({
        repo_name:  currentReport ? currentReport.repo : '',
        built_with: currentReport ? (currentReport.built_with||'') : '',
        findings_summary: findings,
        lite: liteTestMode() ? '1' : '',
        pro_ticket: window._proRunTicket || '',
        stack: currentReport ? (currentReport.stack||[]).map(function(s) { return s && s.name; }).filter(Boolean) : [],
        report_id: savedReportId || ''
      })
    });
    var data = await resp.json();
    stopP2Trickle();
    document.getElementById('p2-loading').style.display = 'none';
    if (data.error) {
      document.getElementById('p2-results').innerHTML = '<div style="background:var(--rdl);border-radius:8px;padding:.85rem;color:var(--rdt);font-size:13px;margin-top:.75rem">' + esc(data.error) + '</div>';
      return;
    }
    window._step4Data = data;
    renderPart2(data);
  } catch(e) {
    stopP2Trickle();
    document.getElementById('p2-loading').style.display = 'none';
    document.getElementById('p2-results').innerHTML = '<div style="background:var(--rdl);border-radius:8px;padding:.85rem;color:var(--rdt);font-size:13px;margin-top:.75rem">Part 2 timed out or failed — this can happen with large or complex apps. <a href=\'#\' onclick=\'runPart2();return false;\' style=\'color:var(--rd);font-weight:600\'>Try again</a> or skip and use the advice prompts above.</div>';
  }
}

// The notice lives in its own element inside the layers group: the old "Loading layers..." line it used
// is hidden as soon as any other layer arrives, which made the message vanish.
function layerErrorsHTML() {
  return (window._layerErrorMsgs || []).map(function(m) {
    return '<div style="display:flex;gap:8px;align-items:flex-start;background:var(--orl);color:var(--ort);border-radius:8px;padding:.6rem .8rem;margin:.4rem 0;font-size:13px">' +
           '<i class="ti ti-alert-triangle" style="font-size:16px;flex-shrink:0"></i><span>' + esc(m) + '</span></div>';
  }).join('');
}

function showLayerError(msg) {
  window._layerErrorMsgs = (window._layerErrorMsgs || []).concat([String(msg)]);
  var box = document.getElementById('layer-errors');
  if (box) box.innerHTML = layerErrorsHTML();
  var loadingEl = document.getElementById('layers-loading');
  if (loadingEl) loadingEl.style.display = 'none';
}

function appendLayers(newLayers) {
  var nav = document.getElementById('layer-nav');
  if (!nav) return;

  // Results stream in over 30+ seconds while someone may already be reading
  // further down the page — the biggest single jump was the "Loading
  // layers..." placeholder suddenly becoming a full layer's worth of real
  // content (auto-selected below, this same function) at whatever point in
  // the page that placeholder happened to be. If the reader has already
  // scrolled to or past that point, compensate the scroll by however much
  // the page grew so whatever they're looking at doesn't visibly move.
  // Someone still above it gets the normal "content filling in below them"
  // behaviour untouched — no compensation needed there.
  var scrollAnchor = document.getElementById('layers-loading') || nav;
  var anchorTop = scrollAnchor.getBoundingClientRect().top + window.scrollY;
  var pastAnchor = window.scrollY >= anchorTop - 40;
  var heightBefore = document.body.scrollHeight;

  var icons = {Auth:'ti-shield',Database:'ti-database',Config:'ti-lock',Frontend:'ti-layout',Libraries:'ti-package',API:'ti-api','File Handling':'ti-file'};
  var sdot = {critical:'#E24B4A',warning:'#EF9F27',passing:'#639922',not_checked:'#888780'};
  var sibg = {critical:'var(--rdl)',warning:'var(--orl)',passing:'var(--grl)',not_checked:'#F1EFE8'};
  var siclr = {critical:'var(--rdt)',warning:'var(--ort)',passing:'var(--grt)',not_checked:'#5F5E5A'};

  // An area the AI answer left out arrives as "not_checked": the scan is incomplete, so no grade is shown.
  newLayers.forEach(function(l) {
    if (l && l.status === 'not_checked') {
      window._incompleteLayers = window._incompleteLayers || [];
      if (window._incompleteLayers.indexOf(l.name) === -1) window._incompleteLayers.push(l.name);
    }
  });

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
      '<span style="flex:1">' + esc(layer.name) + '</span>' + layerCountChip(layer) +
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

  // Now that real findings are in, compute the score/counts from them and fill the header.
  updateHealthDisplay();

  if (pastAnchor) {
    var delta = document.body.scrollHeight - heightBefore;
    if (delta > 0) window.scrollBy(0, delta);
  }
}

// "Check it yourself": static steps written by hand on the server (verilay_selfcheck.py); everything is escaped here.
function renderSelfCheck(items) {
  if (!items || !items.length) return '';
  var mins = 0, body = '';
  items.forEach(function(it) {
    if (it.id === 'needs_person') {
      body += '<div style="font-size:13px;color:#444;margin:.5rem 0"><strong>' + esc(it.title) + '.</strong> ' + esc(it.note) + '</div>';
      return;
    }
    mins += it.minutes || 0;
    body += '<div style="margin:.5rem 0 .75rem"><div style="font-size:13px;font-weight:600">' + esc(it.title) + '</div>' +
      '<ol style="font-size:13px;color:#444;line-height:1.55;margin:.3rem 0 .3rem 1.2rem">' +
      (it.steps || []).map(function(st) { return '<li>' + esc(st) + '</li>'; }).join('') + '</ol>' +
      '<div style="font-size:13px;color:#27500A">&#10003; ' + esc(it.good) + '</div>' +
      '<div style="font-size:13px;color:#791F1F">&#9888; ' + esc(it.bad) + '</div>' +
      '<div style="font-size:12px;color:#6b6966;margin-top:.2rem">' + esc(it.limit) + '</div></div>';
  });
  var when = mins ? ' &middot; about ' + mins + ' minute' + (mins === 1 ? '' : 's') : '';
  return '<details class="selfcheck" style="margin:.6rem 0 0;background:#F8F8FC;border-radius:8px;padding:.6rem .8rem">' +
    '<summary style="cursor:pointer;font-size:13px;font-weight:600;color:#534AB7">Check it yourself' + when + '</summary>' + body +
    '<div style="font-size:12px;color:#6b6966;border-top:0.5px solid #e5e5f0;padding-top:.4rem">Only try this on your own app, with test accounts. Never on someone else\'s app.</div></details>';
}

// "Site setup": what a live address shows about how it is set up, with how to fix each item. The wording comes from the server
// (verilay_sitecheck.py); every value is escaped here. Prompts are kept in a list and copied by number, so no text sits inside an attribute.
window._sitePrompts = window._sitePrompts || [];
function copySitePrompt(i) {
  var p = window._sitePrompts[i];
  if (!p || !navigator.clipboard) return;
  navigator.clipboard.writeText(p).then(function() {
    var b = document.getElementById("site-copy-" + i);
    if (b) { var t = b.textContent; b.textContent = "Copied"; setTimeout(function() { b.textContent = t; }, 2500); }
  });
}
function siteFixHTML(steps, code, prompt, intro) {
  var h = "";
  var pre = "font-size:12px;background:var(--bg2,#f4f3ee);border-radius:6px;padding:.5rem;overflow-x:auto;white-space:pre-wrap;margin:.3rem 0";
  if (intro) h += "<div style=\"font-size:12.5px;font-weight:600;margin:.3rem 0\">" + esc(intro) + "</div>";
  h += "<ol style=\"font-size:12.5px;line-height:1.6;margin:.2rem 0 .4rem 1.1rem;padding:0\">" + (steps || []).map(function(s) { return "<li>" + esc(s) + "</li>"; }).join("") + "</ol>";
  if (code) h += "<pre style=\"" + pre + "\">" + esc(code) + "</pre>";
  if (prompt) {
    var i = window._sitePrompts.push(prompt) - 1;
    h += "<div style=\"font-size:12px;color:var(--mut);margin-top:.3rem\">Or paste this into your AI builder:</div><pre style=\"" + pre + "\">" + esc(prompt) + "</pre>" +
      "<button type=\"button\" id=\"site-copy-" + i + "\" onclick=\"copySitePrompt(" + i + ")\" style=\"font-size:12px;padding:4px 10px;border:0.5px solid var(--bdr);border-radius:6px;background:var(--bg);cursor:pointer\">Copy prompt</button>";
  }
  return h;
}
function siteSetupHTML(sv) {
  if (!sv || !sv.has) return "";
  window._sitePrompts = [];
  var c = sv.counts || {};
  var h = "<div style=\"font-size:13px;font-weight:600;margin:.9rem 0 .3rem\">Site setup: what to fix</div>" +
    "<div style=\"font-size:13px;line-height:1.6\"><strong>" + esc(c.check || 0) + " worth fixing, " + esc(c.ok || 0) + " fine.</strong> This looks like it runs on " + esc(sv.platform_label) + ", so the steps are for that.</div>";
  if (sv.header_fix) {
    var hf = sv.header_fix;
    h += "<details style=\"margin-top:.6rem\"><summary style=\"cursor:pointer;font-size:13px;font-weight:600;color:var(--pu)\">&ndash; Security headers: how to fix</summary>" + siteFixHTML(hf.steps, hf.code, hf.prompt, hf.intro) + "</details>";
  }
  (sv.items || []).forEach(function(it) {
    var mark = it.status === "ok" ? ["&#10003;", "#1D9E75"] : (it.status === "check" ? ["&ndash;", "#92400E"] : ["&middot;", "#6b6966"]);
    var head = "<span style=\"color:" + mark[1] + ";font-weight:700\">" + mark[0] + "</span> <strong style=\"font-size:13px\">" + esc(it.title) + "</strong>" +
      "<span style=\"font-size:12.5px;color:var(--mut)\"> &mdash; " + esc(it.detail || "") + "</span>";
    if (it.status === "check") {
      h += "<details style=\"margin-top:.6rem\"><summary style=\"cursor:pointer\">" + head + "</summary><div style=\"font-size:12.5px;line-height:1.6;margin:.3rem 0\">" + esc(it.why) + "</div>" + siteFixHTML(it.steps, it.code, it.prompt) + "</details>";
    } else {
      h += "<div style=\"margin-top:.5rem\">" + head + "</div>";
    }
  });
  h += "<div style=\"font-size:12px;color:var(--mut);margin-top:.7rem\">" + esc(sv.prompt_note) + " " + esc(sv.note) + "</div>";
  return h;
}

// A live-address preview: what could be read from outside, tests to try, and the next step. The wording comes from the server
// (verilay_livecheck.py); every value is escaped here.
function liveCheckHTML(data) {
  var v = data && data.live_view;
  if (!v) return "";
  var names = data.files_analysed;
  var n = Array.isArray(names) ? names.filter(function(x) { return String(x).charAt(0) !== "_"; }).length : (data.files_read || 0);
  var h = "<div style=\"font-size:13px;line-height:1.6\">Verilay read the page your browser receives from this address, plus its script files" +
    (n ? " (" + n + " file" + (n === 1 ? "" : "s") + " in all)" : "") +
    ". It ran fixed checks on them for exposed keys and passwords and for weak hashing patterns, and read the security headers and outside scripts shown below.</div>" +
    "<div style=\"font-size:13px;line-height:1.6;margin-top:.5rem\"><strong>It can't see</strong> " + esc(v.limits) +
    ". So &ldquo;not graded&rdquo; means &ldquo;not enough to grade&rdquo;, not &ldquo;fine&rdquo;.</div>";
  if (v.headers) {
    h += "<div style=\"font-size:13px;font-weight:600;margin:.9rem 0 .3rem\">Security headers this site sends</div>";
    h += "<div style=\"font-size:13px;margin-bottom:.3rem\">" + (v.https ? "This address uses a secure (https) connection." : "This address does not use a secure (https) connection.") + "</div>";
    v.headers.forEach(function(r) {
      var word = r.sent ? "sent" : (r.covered ? "covered by the Content-Security-Policy" : "not seen");
      var colour = (r.sent || r.covered) ? "#1D9E75" : "#92400E";
      h += "<div style=\"padding:.4rem 0;border-top:0.5px solid var(--bdr)\"><span style=\"font-family:monospace;font-size:12.5px\">" + esc(r.name) + "</span> " +
        "<span style=\"color:" + colour + ";font-size:12.5px;font-weight:600\">" + ((r.sent || r.covered) ? "&#10003; " : "&ndash; ") + esc(word) + "</span>" +
        "<div style=\"font-size:12.5px;color:var(--mut)\">" + esc(r.plain) + "</div></div>";
    });
    h += "<div style=\"font-size:12px;color:var(--mut);margin-top:.4rem\">" + esc(v.header_note) + "</div>";
  }
  if (v.scripts) {
    h += "<div style=\"font-size:13px;font-weight:600;margin:.9rem 0 .3rem\">Outside scripts this page loads</div>";
    if (v.scripts.length) {
      h += "<div style=\"font-size:13px;line-height:1.6\">The main page loads scripts from other sites: " +
        v.scripts.map(function(x) { return "<span style=\"font-family:monospace;font-size:12.5px\">" + esc(x) + "</span>"; }).join(", ") + ".</div>" +
        "<div style=\"font-size:12px;color:var(--mut);margin-top:.3rem\">" + esc(v.scripts_note) + "</div>";
    } else {
      h += "<div style=\"font-size:13px\">The main page loads no scripts from other sites.</div>";
    }
  }
  h += siteSetupHTML(data && data.site_view);
  h += "<div style=\"font-size:13px;font-weight:600;margin:.9rem 0 .2rem\">Check it yourself on your live site</div>" +
    "<div style=\"font-size:13px;line-height:1.6\">These are the tests a scanner can't do from outside. Try them on your own site.</div>" +
    renderSelfCheck(v.check_detail);
  h += "<div style=\"font-size:13px;font-weight:600;margin:.9rem 0 .2rem\">Want a real review?</div>" +
    "<div style=\"font-size:13px;line-height:1.6\">" + esc(v.next_step) + "</div>";
  return h;
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
      'Green = no known vulnerabilities found. Red = vulnerable packages detected. This is checked directly against OSV.dev, a public vulnerability database — see the Libraries section above for the count.'],
    ['no_hardcoded_secrets','No hardcoded secrets in code',false,
      'Hardcoded secrets (like API keys written directly in code) are visible to anyone who views your source. They should always be in environment variables instead.',
      'Green = no hardcoded keys found in visible code. Red = potential secrets detected in source. Surface scans can only check client-side code.']
  ];
  var _ckStart = html.length;          // the checklist goes into "More" (28 Oct 2026)
  html += '<div style="font-size:12px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin-bottom:.5rem">Security checklist</div>';
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
    html += '<i class="ti ' + ico + '" style="font-size:16px;flex-shrink:0"></i>';
    html += '<span style="flex:1;font-weight:500">' + c[1] + '</span>';
    html += '<i class="ti ti-chevron-down" style="font-size:13px;opacity:.6" id="' + checkId + '-ico"></i>';
    html += '</div>';
    html += '<div id="' + checkId + '" style="display:none;margin-top:.6rem;padding-top:.6rem;border-top:0.5px solid currentColor;opacity:.8;width:100%">';
    html += '<div style="font-size:12px;font-weight:600;margin-bottom:.3rem">Why it matters:</div>';
    html += '<div style="font-size:12px;line-height:1.55;margin-bottom:.5rem">' + esc(c[3]||'') + '</div>';
    html += '<div style="font-size:12px;font-weight:600;margin-bottom:.3rem">What this result means:</div>';
    html += '<div style="font-size:12px;line-height:1.55">' + esc(c[4]||'') + '</div>';
    html += '</div>';
    html += '</div>';
  });
  // Build platform-specific "where to paste" instruction
  var builtWith = (currentReport && currentReport.built_with) ? currentReport.built_with.toLowerCase() : '';
  var _builder  = builderFromBuiltWith(currentReport && currentReport.built_with);   // its opening words only
  var isLovable = _builder === 'Lovable';
  var isReplit  = _builder === 'Replit';
  var isBolt    = _builder === 'Bolt';
  var isV0      = _builder === 'v0';

  var whereToGo = 'your AI builder chat';
  var whereDetail = 'Open your AI builder and paste the prompt into the chat';
  if (isLovable) { whereToGo = 'Lovable'; whereDetail = 'Go to lovable.dev → open your project → paste in the chat box'; }
  if (isReplit) { whereToGo = 'Replit'; whereDetail = 'Go to replit.com → open your project → paste in the Replit AI chat'; }
  if (isBolt) { whereToGo = 'Bolt'; whereDetail = 'Go to bolt.new → open your project → paste in the chat'; }
  if (isV0) { whereToGo = 'v0'; whereDetail = 'Go to v0.dev → open your project → paste in the chat'; }

  var _ckEnd = html.length;
  html += '<div style="font-size:12px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin:.85rem 0 .5rem">Fix prompts</div>';
  html += '<div style="background:var(--pul);border:0.5px solid var(--pu);border-radius:8px;padding:.75rem 1rem;margin-bottom:.75rem;font-size:13px;color:var(--put);line-height:1.6">';
  html += '<strong>How to use these:</strong> ';
  html += whereDetail + '. ';
  html += 'Copy each prompt, read what ' + whereToGo + ' says, then paste their response back here to verify. ';
  html += '<strong>Do not apply changes until ' + whereToGo + ' confirms it is safe.</strong>';
  html += '</div>';
  html += '<div style="font-size:12px;color:var(--mut);margin-bottom:.75rem">Note: there is one advice prompt per finding, most serious first. Take each to your AI builder to review and advise — don\'t apply changes until it confirms what\'s genuinely needed.</div>';

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

    // <details> instead of a plain <div> -- collapsed by default so a
    // non-developer can open one fix at a time instead of facing every
    // fix's full advice prompt expanded at once. Summary shows just enough
    // (priority + title) to decide whether to open it.
    html += '<details class="fc"' + (fi === 0 ? ' open' : '') + '><summary style="cursor:pointer;display:flex;gap:12px;align-items:center">';
    html += '<div style="width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:600;flex-shrink:0;background:var(--pul);color:var(--put)">' + (f.priority||'') + '</div>';
    var fixLabel = [f.area || '', (f.tech && f.tech.length) ? f.tech.join(', ') : ''].filter(Boolean).join(' · ');
    html += '<div style="flex:1"><div style="font-size:14px;font-weight:500">' + esc(f.title||'') + '</div>' +
            (fixLabel ? '<div style="font-size:11px;color:var(--mut);margin-top:2px">' + esc(fixLabel) + '</div>' : '') + '</div>';
    html += '</summary><div style="padding-top:.5rem">';
    html += '<div style="font-size:13px;color:var(--mut);margin-bottom:4px;line-height:1.4">' + esc(f.why_it_matters||'') + '</div>';
    html += '<div style="font-size:12px;background:var(--bg);border-radius:6px;padding:5px 8px;color:var(--mut);line-height:1.5;margin-bottom:.5rem">' + esc(f.how_to_fix||'') + '</div>';
    html += '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">';
    html += '<span style="font-size:12px;font-weight:500;padding:2px 8px;border-radius:20px;background:var(--pul);color:var(--put)">' + esc(f.estimated_effort||'varies') + '</span>';
    if (platformPrompt) {
      html += '<button id="fix-btn-' + fi + '" style="display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:500;padding:4px 12px;border-radius:20px;background:var(--pu);color:#fff;border:none;cursor:pointer">';
      html += '<i class="ti ' + platformIcon + '" style="font-size:13px"></i> ' + platformLabel;
      html += '</button>';
      html += '<span id="fix-copied-' + fi + '" style="font-size:12px;color:var(--grt);display:none">✓ Copied! Paste into your AI chat</span>';
    }
    html += '</div>';
    if (platformPrompt) {
      html += '<div style="margin-top:.5rem;background:var(--bg);border-radius:6px;padding:.5rem .75rem;font-size:12px;font-family:monospace;color:var(--mut);white-space:pre-wrap;word-break:break-all;max-height:80px;overflow:hidden;line-height:1.5" id="fix-prompt-' + fi + '">' + esc(platformPrompt) + '</div>';
    }
    html += renderSelfCheck(f.check_detail);
    html += '</div></details>';
  });

  // Light free scan: the other fix prompts are part of Verilay Pro (a folded, locked row, then the Pro card).
  if (data.lite) {
    var _hh = (currentReport && currentReport.health) || {};
    var _more = Math.max(0, (_hh.critical || 0) + (_hh.warnings || 0) - (data.top_fixes || []).length);
    if (_more) html += '<details class="fc" style="opacity:.6"><summary style="cursor:pointer;font-size:14px;font-weight:600">&#128274; ' + _more + ' more fix prompt' +
      (_more === 1 ? '' : 's') + ' (Verilay Pro)</summary><div style="font-size:13px;color:var(--mut);padding:.4rem 0">Included in Verilay Pro' +
      ((data.pro_launch && data.pro_launch.active) ? ', free during the launch' : '') + '. See below.</div></details>';
    html += proLockedHTML(data);
  }

  // Wire fix buttons after render
  setTimeout(function() {
    bindProEarlyAccess();
    showProTopBanner(data);
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
            setTimeout(showRatingNudge, 2500);          // the moment Verilay has just helped: ask once
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
  var _xStart = html.length;           // "Recommended next steps" and the second opinions go into "More" (28 Oct 2026)
  // Next steps recommendation
  html += '<div style="background:var(--pul);border-radius:var(--r);padding:.85rem 1rem;margin:.85rem 0;border-left:3px solid var(--pu)">';
  html += '<div style="font-size:13px;font-weight:600;color:var(--put);margin-bottom:.4rem"><i class="ti ti-arrow-right" style="margin-right:4px"></i>Recommended next steps</div>';
  html += '<div style="font-size:13px;color:var(--put);line-height:1.6">';
  html += 'Verilay gives you a first-pass overview - good for understanding and catching obvious issues. For production apps we recommend going further:<br>';
  html += '• <a href="https://snyk.io" target="_blank" style="color:var(--pu)">Snyk</a> - free dependency and vulnerability scanning (connects to GitHub)<br>';
  html += '• <a href="https://coderabbit.ai" target="_blank" style="color:var(--pu)">CodeRabbit</a> - AI code review on every pull request (free for open source)<br>';
  html += '• Share the second opinion prompts below with a developer for a human review<br>';
  html += '• Fix all critical issues before going live with real users or payments';
  html += '</div></div>';

  html += '<div style="font-size:12px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin:.85rem 0 .5rem">Second opinion - verify with any AI</div>';
  html += '<div style="font-size:13px;color:var(--mut);margin-bottom:.75rem">Copy any prompt into Claude or ChatGPT to independently verify findings.</div>';
  soItems.forEach(function(item) {
    if (!item[1]) return;
    html += '<div class="so-card"><div style="font-size:13px;font-weight:500;margin-bottom:.4rem;display:flex;align-items:center;gap:6px"><i class="ti ' + item[2] + '" style="font-size:15px;color:var(--pu)"></i>' + item[0] + '</div>';
    html += '<div style="background:var(--bg);border-radius:6px;padding:.6rem .75rem;font-size:12px;font-family:monospace;color:var(--mut);white-space:pre-wrap;word-break:break-all;max-height:150px;overflow-y:auto;line-height:1.5">' + esc(item[1]) + '</div>';
    html += '<div style="display:flex;gap:6px;margin-top:.5rem">';
    html += '<a href="https://claude.ai" target="_blank" style="font-size:12px;padding:4px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--txt);text-decoration:none">Open Claude</a>';
    html += '<a href="https://chat.openai.com" target="_blank" style="font-size:12px;padding:4px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--txt);text-decoration:none">Open ChatGPT</a>';
    html += '</div></div>';
  });
  var _checklist = html.slice(_ckStart, _ckEnd);
  var _extras = html.slice(_xStart);
  html = html.slice(0, _ckStart) + html.slice(_ckEnd, _xStart) + '</div>';
  document.getElementById('p2-results').innerHTML = html;
  window._p2Fixes = data.top_fixes || null;
  window._moreExtra = [['sec-checklist', 'Security checklist', secHtml('sec-checklist', 'Security checklist', 'Quick checks with what each one means', _checklist, false)],
                       ['sec-second', 'Second opinions', secHtml('sec-second', 'Second opinions and next steps', 'Prompts to verify the findings with any AI, and tools to go further', _extras, false)]];
  renderMoreBox((window._moreBase || []).concat(window._moreExtra), true);
  refreshStartHere();
  refreshAskChips();
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
      headers: reportHeaders(savedReportId, {'Content-Type': 'application/json'}),
      body: JSON.stringify({
        report_id: savedReportId,
        finding_key: findingKey,
        builder_response: builderResponse,
        verdict: verdict
      })
    });
    var data = await resp.json();
    if (!data.ok) {
      alert(data.error || 'Could not save this check. Please try again.');
      return;
    }
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
        verifiedDiv.style.cssText = 'margin-top:8px;padding:6px 10px;background:#F0FDF4;border:0.5px solid #22C55E;border-radius:6px;font-size:12px;color:#166534';
        verifiedDiv.innerHTML = '<strong>✅ Verified by AI builder</strong>' +
          (verdict === 'false_positive' ? ' — confirmed not an issue' : verdict === 'fixed' ? ' — confirmed fixed' : ' — verified real issue') +
          (builderResponse ? '<div style="margin-top:3px;opacity:.8;font-size:12px">' + builderResponse.substring(0,120) + (builderResponse.length > 120 ? '...' : '') + '</div>' : '');
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
    existing.style.cssText = 'background:#F0FDF4;border:0.5px solid #22C55E;border-radius:8px;padding:.85rem 1rem;margin-bottom:10px;font-size:13px;color:#166534;line-height:1.6';

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
  // One offer at a time: no waitlist nudge while another offer is on screen.
  if (document.getElementById('compare-card') || document.getElementById('mon-offer') || document.getElementById('pro-locked')) return;

  var nudge = document.createElement('div');
  nudge.id = 'waitlist-nudge';
  nudge.style.cssText = 'position:fixed;bottom:20px;right:20px;width:320px;background:var(--sur);border:0.5px solid var(--pu);border-radius:12px;padding:1.1rem 1.25rem;box-shadow:0 4px 20px rgba(0,0,0,.12);z-index:9999;font-size:14px';
  nudge.innerHTML =
    '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:.5rem">' +
    '<div style="font-weight:600;color:var(--txt)">Enjoying Verilay? 🎉</div>' +
    '<button onclick="dismissWaitlist()" style="background:none;border:none;cursor:pointer;color:var(--mut);font-size:16px;padding:0;line-height:1">×</button>' +
    '</div>' +
    '<div style="color:var(--mut);margin-bottom:.75rem;line-height:1.5">You\'ve run ' + count + ' analyses. We\'re building <strong>persistent history</strong>, <strong>email reports</strong>, and <strong>saved verifications</strong> so your progress carries forward.</div>' +
    '<div style="color:var(--mut);font-size:12px;margin-bottom:.65rem">Join the waitlist — free, no commitment.</div>' +
    '<div style="display:flex;gap:6px">' +
    '<input id="waitlist-email" type="email" placeholder="your@email.com" style="flex:1;font-size:13px;padding:6px 10px;border:0.5px solid var(--bdr);border-radius:6px;background:var(--bg);color:var(--txt)">' +
    '<button onclick="submitWaitlist()" style="font-size:13px;padding:6px 14px;border-radius:6px;background:var(--pu);color:#fff;border:none;cursor:pointer;white-space:nowrap">Join →</button>' +
    '</div>' +
    '<div id="waitlist-msg" style="font-size:12px;margin-top:6px;color:var(--gr);display:none"></div>';

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
  var deletedId = savedReportId;
  try {
    var resp = await fetch('/delete-report/' + deletedId, { method: 'POST', headers: reportHeaders(deletedId) });
    var data = await resp.json();
    if (data.ok) {
      // Clear the report from view. (This used to look for an element called "report", which the
      // page does not have, so it threw after the server had already deleted the report.)
      ['report-sections', 'p2-results', 'layers-container'].forEach(function(i) { var e = document.getElementById(i); if (e) e.innerHTML = ''; });
      ['p2-banner', 'p2-loading', 'steps23-loading', 'share-banner'].forEach(function(i) { var e = document.getElementById(i); if (e) e.style.display = 'none'; });
      var rc = document.getElementById('report-content');
      if (rc) rc.innerHTML = '<div style="text-align:center;padding:2rem;color:var(--mut)">Report deleted.</div>';
      savedReportId = null;
      try { localStorage.removeItem('verilay_tok_' + deletedId); } catch (e) {}
      if (window._reportTokens) delete window._reportTokens[deletedId];
      // Remove from local history
      var history = getHistory();
      var filtered = history.filter(function(h) { return h.id !== deletedId && h._savedId !== deletedId; });
      localStorage.setItem('verilay_history', JSON.stringify(filtered));
    } else {
      alert(data.error || 'Could not delete the report. Please try again.');
    }
  } catch(e) {
    console.error('Delete error:', e);
    alert('Could not delete the report. Please check your connection and try again.');
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
      span.innerHTML = esc(layerName) + ' <span style="font-size:12px;background:#1D9E75;color:#fff;border-radius:8px;padding:1px 5px;margin-left:4px">verified</span>';
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
var lastFeedbackHelpful = null;

// "Did this report help?" nudge (27 Oct 2026, Moses: get more ratings, without forcing anyone). A small card slides up
// once per report: right after a fix prompt is copied (the moment Verilay has just helped), or after a minute of reading.
// One tap rates; the X closes it; either way it never comes back for that report. Never blocks the report.
function _ratedKey() { return 'verilay_rated_' + (savedReportId || ''); }
function _alreadyAsked() {
  if (lastFeedbackHelpful !== null) return true;
  try { return !!localStorage.getItem(_ratedKey()); } catch (e) { return false; }
}
function _markAsked(v) { try { localStorage.setItem(_ratedKey(), v || '1'); } catch (e) {} }
function showRatingNudge() {
  if (!savedReportId || _alreadyAsked() || document.getElementById('rating-nudge')) return;
  var card = document.createElement('div');
  card.id = 'rating-nudge';
  card.setAttribute('role', 'dialog');
  card.setAttribute('aria-label', 'Did this report help?');
  card.style.cssText = 'position:fixed;left:50%;bottom:16px;transform:translateX(-50%);z-index:9999;background:var(--sur);border:0.5px solid var(--pu);' +
    'border-radius:14px;box-shadow:0 6px 24px rgba(26,25,23,.18);padding:.7rem .9rem;display:flex;align-items:center;gap:10px;max-width:calc(100% - 32px)';
  card.innerHTML = '<span style="font-size:14px;font-weight:600;color:var(--txt);white-space:nowrap">Did this report help?</span>' +
    '<button type="button" data-v="up" aria-label="Yes, it helped" style="font-size:20px;background:none;border:0.5px solid var(--bdr);border-radius:8px;padding:4px 12px;cursor:pointer">&#128077;</button>' +
    '<button type="button" data-v="down" aria-label="No, it did not help" style="font-size:20px;background:none;border:0.5px solid var(--bdr);border-radius:8px;padding:4px 12px;cursor:pointer">&#128078;</button>' +
    '<button type="button" data-v="close" aria-label="Close" style="font-size:16px;background:none;border:none;color:var(--mut);cursor:pointer;padding:4px">&#10005;</button>';
  document.body.appendChild(card);
  try { if (typeof plausible === 'function') plausible('Rating Nudge Shown'); } catch (e) {}
  card.querySelectorAll('button').forEach(function(b) {
    b.onclick = function() {
      var v = b.getAttribute('data-v');
      if (v === 'close') { _markAsked('closed'); card.remove(); return; }
      submitFeedback(v === 'up');
      card.innerHTML = '<span style="font-size:14px;color:var(--txt)">Thanks! &#128591; ' +
        '<a href="#feedback-widget" style="color:var(--pu);font-weight:600" onclick="var r=document.getElementById(\'rating-nudge\');if(r)r.remove();">Add a comment</a></span>';
      setTimeout(function() { var r = document.getElementById('rating-nudge'); if (r) r.remove(); }, 6000);
    };
  });
}

function submitFeedback(helpful) {
  lastFeedbackHelpful = helpful;
  _markAsked(helpful ? 'up' : 'down');
  var upBtn = document.getElementById('btn-feedback-up');
  var downBtn = document.getElementById('btn-feedback-down');
  if (upBtn) upBtn.style.background = helpful ? '#EAF3DE' : 'none';
  if (downBtn) downBtn.style.background = !helpful ? '#FCEBEB' : 'none';
  // Record the rating immediately so it's never lost, even if they skip the email step
  postFeedback({ helpful: helpful, comment: '', email: '' });
  // Reveal the optional follow-up (comment + email) for BOTH thumbs up and down
  var txt = document.getElementById('feedback-text');
  if (txt) txt.placeholder = helpful ? 'What did you like? (optional)' : 'What could be better? (optional)';
  var ta = document.getElementById('feedback-text-area');
  if (ta) ta.style.display = 'block';
}

function sendFeedbackText() {
  var text = document.getElementById('feedback-text');
  var emailEl = document.getElementById('feedback-email');
  postFeedback({
    helpful: lastFeedbackHelpful,
    comment: text ? text.value : '',
    email: emailEl ? emailEl.value : ''
  });
  var ta = document.getElementById('feedback-text-area');
  if (ta) ta.style.display = 'none';
  var thanks = document.getElementById('feedback-thanks');
  if (thanks) thanks.style.display = 'block';
  var btns = document.getElementById('btn-feedback-up');
  if (btns) btns.parentElement.style.display = 'none';
}

function postFeedback(payload) {
  fetch('/feedback', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      helpful: payload.helpful,
      comment: payload.comment || '',
      email: payload.email || '',
      report_id: savedReportId || ''
    })
  }).catch(function() {});
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

// Report-grounded Ask Verilay -- unlike askAIAboutReport() above (which just
// hands off to claude.ai), this actually calls Verilay's own /report/<id>/ask
// and shows the answer inline, without leaving the page. Needs no report
// data client-side: the server reads the full saved report itself from
// savedReportId, so this function only needs the question text.
function askAboutReport() {
  var input = document.getElementById('report-ask-input');
  var btn = document.getElementById('report-ask-btn');
  var thread = document.getElementById('report-ask-thread');
  if (!input || !btn || !thread || btn.disabled) return;
  var question = input.value.trim();
  if (!question) return;

  var qBubble = document.createElement('div');
  qBubble.style.cssText = 'align-self:flex-end;max-width:90%;padding:.6rem .85rem;border-radius:12px;border-bottom-right-radius:3px;background:var(--pu);color:#fff;font-size:13px;white-space:pre-wrap;word-wrap:break-word';
  qBubble.textContent = question;
  thread.appendChild(qBubble);

  var aBubble = document.createElement('div');
  aBubble.style.cssText = 'align-self:flex-start;max-width:90%;padding:.6rem .85rem;border-radius:12px;border-bottom-left-radius:3px;background:var(--bg);border:0.5px solid var(--bdr);color:var(--txt);font-size:13px;line-height:1.55';
  aBubble.textContent = 'Thinking…';
  thread.appendChild(aBubble);
  aBubble.scrollIntoView({behavior: 'smooth', block: 'end'});

  input.value = '';
  input.disabled = true;
  btn.disabled = true;
  btn.style.opacity = '.5';
  btn.style.cursor = 'not-allowed';

  fetch('/report/' + savedReportId + '/ask', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({question: question})
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (d.ok) {
      aBubble.innerHTML = md(d.answer || '');
    } else if (d.limit_reached) {
      aBubble.style.cssText = 'align-self:center;max-width:100%;padding:.6rem .85rem;border-radius:10px;background:var(--pul);border:0.5px solid var(--pu);color:var(--put);font-size:12px;text-align:center';
      aBubble.textContent = d.error || 'You have reached the free limit for this report.';
    } else {
      aBubble.textContent = d.error || 'Something went wrong answering that. Please try again.';
    }
  }).catch(function() {
    aBubble.textContent = 'Something went wrong answering that. Please try again.';
  }).finally(function() {
    input.disabled = false;
    btn.disabled = false;
    btn.style.opacity = '1';
    btn.style.cursor = 'pointer';
    input.focus();
  });
}

document.addEventListener('DOMContentLoaded', init);

// Print / PDF: a collapsed group would print as just its title, so open them all for the print job.
window.addEventListener('beforeprint', function() {
  document.querySelectorAll('details.sec').forEach(function(d) { d.dataset.wasOpen = d.open ? '1' : '0'; d.open = true; });
});
window.addEventListener('afterprint', function() {
  document.querySelectorAll('details.sec').forEach(function(d) { d.open = d.dataset.wasOpen === '1'; });
});
