/*
 * Phishing Email Analyser - the user interface.
 *
 * This file connects the buttons on the page to the analysis engine
 * (analyser.js) and draws the report. Everything is written into the page
 * as plain text, so nothing from a pasted email can run as code, and links
 * are never made clickable.
 */
(function () {
  'use strict';

  var A = window.PhishAnalyser;
  var SAMPLES = window.PHISH_SAMPLES || [];

  var input = document.getElementById('email-input');
  var charCount = document.getElementById('char-count');
  var analyseBtn = document.getElementById('analyse-btn');
  var clearBtn = document.getElementById('clear-btn');
  var emptyState = document.getElementById('empty-state');
  var report = document.getElementById('report');

  // Small helper to build page elements safely (text is never treated as HTML).
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'class') node.className = attrs[k];
        else if (k === 'text') node.textContent = attrs[k];
        else node.setAttribute(k, attrs[k]);
      });
    }
    (children || []).forEach(function (c) {
      if (c == null) return;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return node;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  // ---- Demo buttons -------------------------------------------------------
  var sampleList = document.getElementById('sample-list');
  SAMPLES.forEach(function (s) {
    var b = el('button', { type: 'button', class: 'chip', 'data-id': s.id, text: s.label });
    b.addEventListener('click', function () {
      input.value = s.text;
      updateCount();
      run();
      if (window.innerWidth < 900) report.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    sampleList.appendChild(b);
  });

  // ---- Rules table ("How the score works") -------------------------------
  var rulesBody = document.querySelector('#rules-table tbody');
  A.RULES.forEach(function (r) {
    rulesBody.appendChild(el('tr', null, [
      el('td', null, [el('strong', { text: r.name }), el('span', { class: 'rule-why', text: r.why })]),
      el('td', { text: r.category }),
      el('td', { class: 'num', text: '+' + r.points })
    ]));
  });

  // ---- Input events -------------------------------------------------------
  function updateCount() {
    var n = input.value.length;
    charCount.textContent = n.toLocaleString() + ' character' + (n === 1 ? '' : 's');
  }
  input.addEventListener('input', updateCount);
  input.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); run(); }
  });
  analyseBtn.addEventListener('click', run);
  clearBtn.addEventListener('click', function () {
    input.value = '';
    updateCount();
    report.hidden = true;
    emptyState.hidden = false;
    input.focus();
  });

  // ---- Run the analysis and draw the report -------------------------------
  function run() {
    var text = input.value;
    if (!text.trim()) {
      input.focus();
      input.classList.add('shake');
      setTimeout(function () { input.classList.remove('shake'); }, 400);
      return;
    }
    var result = A.analyse(text);
    render(result, text.replace(/\r\n?/g, '\n'));
  }

  function render(r, text) {
    emptyState.hidden = true;
    report.hidden = false;
    report.setAttribute('data-level', r.band.level);

    // Gauge
    var circumference = 2 * Math.PI * 50;
    var fill = document.getElementById('gauge-fill');
    fill.style.strokeDasharray = circumference;
    fill.style.strokeDashoffset = circumference;
    requestAnimationFrame(function () {
      requestAnimationFrame(function () { fill.style.strokeDashoffset = circumference * (1 - r.score / 100); });
    });
    animateNumber(document.getElementById('score-value'), r.score);
    document.getElementById('risk-pill').textContent = r.band.label;
    document.getElementById('risk-summary').textContent = r.band.summary;

    // Quick facts
    var stats = document.getElementById('stats');
    clear(stats);
    var authText = !r.stats.authFound ? 'Not included'
      : r.stats.authPasses.length ? r.stats.authPasses.map(function (s) { return s.toUpperCase(); }).join(', ') + ' passed'
      : 'No passes';
    [
      ['Warning signs', String(r.indicators.length)],
      ['Links found', String(r.stats.links)],
      ['Attachment names', String(r.stats.attachments)],
      ['Email headers', r.stats.headersFound ? 'Included' : 'Not included'],
      ['SPF / DKIM / DMARC', authText]
    ].forEach(function (s) {
      stats.appendChild(el('div', { class: 'stat' }, [el('span', { class: 'stat-label', text: s[0] }), el('span', { class: 'stat-value', text: s[1] })]));
    });

    // Indicators
    var list = document.getElementById('indicator-list');
    clear(list);
    document.getElementById('indicator-count').textContent = r.indicators.length;
    if (!r.indicators.length) {
      list.appendChild(el('div', { class: 'none-found' }, [
        el('strong', { text: 'No common warning signs were detected.' }),
        el('span', { text: ' That is a good sign, but it does not prove the email is genuine. Stay cautious with any request involving money, passwords or codes.' })
      ]));
    }
    r.indicators.forEach(function (ind, i) {
      var evidence = el('ul', { class: 'evidence' }, ind.evidence.map(function (e) {
        return el('li', null, [el('code', { text: shorten(e.text, 140) }), e.note ? el('span', { class: 'ev-note', text: e.note }) : null]);
      }));
      var card = el('details', { class: 'indicator sev-' + severity(ind.points) }, [
        el('summary', null, [
          el('span', { class: 'ind-points', text: '+' + ind.points }),
          el('span', { class: 'ind-main' }, [el('span', { class: 'ind-name', text: ind.name }), el('span', { class: 'ind-cat', text: ind.category })]),
          el('span', { class: 'chev', 'aria-hidden': 'true' })
        ]),
        el('div', { class: 'ind-body' }, [
          el('p', { class: 'ind-why' }, [el('strong', { text: 'Why this matters: ' }), ind.why]),
          el('p', { class: 'ind-evlabel', text: 'Found in the email:' }),
          evidence
        ])
      ]);
      if (i < 2) card.open = true;
      list.appendChild(card);
    });

    // Breakdown table
    var table = document.getElementById('breakdown');
    clear(table);
    var tbody = el('tbody');
    r.indicators.forEach(function (ind) {
      tbody.appendChild(el('tr', null, [el('td', { text: ind.name }), el('td', { class: 'num', text: '+' + ind.points })]));
    });
    if (!r.indicators.length) tbody.appendChild(el('tr', null, [el('td', { text: 'No warning signs' }), el('td', { class: 'num', text: '0' })]));
    var foot = el('tfoot');
    if (r.rawTotal > 100) {
      foot.appendChild(el('tr', { class: 'sub' }, [el('td', { text: 'Points added up' }), el('td', { class: 'num', text: String(r.rawTotal) })]));
      foot.appendChild(el('tr', { class: 'sub' }, [el('td', { text: 'Capped at the maximum' }), el('td', { class: 'num', text: '100' })]));
    }
    foot.appendChild(el('tr', null, [el('td', { text: 'Risk score' }), el('td', { class: 'num', text: r.score + ' / 100' })]));
    table.appendChild(tbody);
    table.appendChild(foot);

    // Recommendations
    var recs = document.getElementById('recs');
    clear(recs);
    r.recommendations.forEach(function (t) { recs.appendChild(el('li', { text: t })); });

    // Highlighted copy of the email
    renderHighlights(document.getElementById('highlighted'), text, r.indicators);
  }

  function severity(points) { return points >= 20 ? 'high' : points >= 15 ? 'medium' : 'low'; }

  function shorten(s, n) { s = s.replace(/\s+/g, ' '); return s.length > n ? s.slice(0, n - 1) + '…' : s; }

  function animateNumber(node, target) {
    var start = null, from = 0, dur = 700;
    function step(ts) {
      if (start === null) start = ts;
      var p = Math.min(1, (ts - start) / dur);
      node.textContent = Math.round(from + (target - from) * (1 - Math.pow(1 - p, 3)));
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  // Mark every piece of evidence in the original text. Overlapping matches
  // are merged so the text stays readable.
  function renderHighlights(pre, text, indicators) {
    clear(pre);
    var ranges = [];
    indicators.forEach(function (ind) {
      ind.evidence.forEach(function (e) {
        if (typeof e.index === 'number' && e.index >= 0 && e.length > 0) {
          ranges.push({ s: e.index, e: e.index + e.length, label: ind.name, sev: severity(ind.points) });
        }
      });
    });
    ranges.sort(function (a, b) { return a.s - b.s || b.e - a.e; });
    var merged = [];
    ranges.forEach(function (r) {
      var last = merged[merged.length - 1];
      if (last && r.s < last.e) {
        last.e = Math.max(last.e, r.e);
        if (last.labels.indexOf(r.label) === -1) last.labels.push(r.label);
        if (r.sev === 'high' || (r.sev === 'medium' && last.sev === 'low')) last.sev = r.sev;
      } else {
        merged.push({ s: r.s, e: r.e, labels: [r.label], sev: r.sev });
      }
    });
    var pos = 0;
    merged.forEach(function (m) {
      if (m.s > pos) pre.appendChild(document.createTextNode(text.slice(pos, m.s)));
      pre.appendChild(el('mark', { class: 'hl-' + m.sev, title: m.labels.join(', '), text: text.slice(m.s, m.e) }));
      pos = m.e;
    });
    if (pos < text.length) pre.appendChild(document.createTextNode(text.slice(pos)));
  }

  updateCount();
})();
