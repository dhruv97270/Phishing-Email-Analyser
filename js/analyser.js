/*
 * Phishing Email Analyser - the analysis engine (version 2).
 *
 * Everything in this file runs inside your own web browser. Nothing is ever
 * sent anywhere: there are no network calls in this project at all.
 *
 * How it works, in plain English:
 *   1. DECODE   Raw emails ("Show original" / .eml files) are often encoded
 *               (quoted-printable, base64) and full of HTML code. We decode
 *               them and keep only the text a person would actually see.
 *   2. EXTRACT  We pull out the headers, links (including where each link
 *               really goes), attachments and the sender's domain.
 *   3. RULES    Each rule looks for one warning sign and adds FIXED points.
 *               "Reassuring" rules (a verified sender) take points away.
 *   4. CONTEXT  An email only reaches High Risk if it contains a dangerous
 *               ask (password, payment, attachment...) or a forged sender.
 *   5. RESULT   The total is kept between 0 and 100 and turned into
 *               Low / Suspicious / High, with every step shown to the user.
 *
 * To change how strict the tool is, edit the "points" value of a rule below.
 */
(function (global) {
  'use strict';

  // ---------------------------------------------------------------------
  // Score bands. A score at or above "min" gets that label.
  // ---------------------------------------------------------------------
  var BANDS = [
    { min: 60, label: 'High Risk', level: 'high',
      summary: 'Several strong phishing warning signs were found. Treat this message as dangerous until you have verified it through an official channel.' },
    { min: 30, label: 'Suspicious', level: 'medium',
      summary: 'Some warning signs were found. Do not act on this message until you have checked it independently.' },
    { min: 0, label: 'Low Risk', level: 'low',
      summary: 'Few or no serious warning signs were found. That does not prove the message is safe; skilled attackers can avoid every pattern this tool checks.' }
  ];

  // Context limits (see step 4 above).
  var CAP_NO_DANGER = 59;          // no dangerous ask -> at most Suspicious
  var CAP_VERIFIED_NO_DANGER = 29; // verified sender and no dangerous ask -> Low
  var TRUST_LIMIT_WITH_DANGER = 0;   // a verified sender cannot reduce a dangerous email's score

  // Well-known URL shortening services. A short link hides the real destination.
  var SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 't.ly',
    'bl.ink', 's.id', 'v.gd', 'qrco.de', 'shorte.st', 'adf.ly'
  ];

  // Email-marketing and link-protection services. Legitimate companies route
  // their links through these to count clicks, so a link through them is
  // normal, not suspicious by itself.
  var TRACKERS = [
    'sendgrid.net', 'list-manage.com', 'mailchi.mp', 'mcusercontent.com', 'mandrillapp.com',
    'amazonses.com', 'awstrack.me', 'sparkpostmail.com', 'hubspotlinks.com', 'hubspotemail.net',
    'hs-analytics.net', 'exacttarget.com', 'sfmc-content.com', 'braze.com', 'braze.eu',
    'klaviyomail.com', 'klclick.com', 'klclick1.com', 'customeriomail.com', 'iterable.com',
    'rs6.net', 'createsend1.com', 'cmail19.com', 'cmail20.com', 'mailgun.org', 'mailgun.net',
    'pstmrk.it', 'postmarkapp.com', 'urldefense.com', 'safelinks.protection.outlook.com',
    'mimecastprotect.com', 'mktossl.com', 'mkto-lp.com', 'cmail1.com', 'eloqua.com', 'en25.com',
    'emltrk.com', 'bnc3.mailjet.com', 'mjt.lu', 'sendibt3.com', 'sendinblue.com', 'brevo.com'
  ];

  // Free email providers: anyone can make an account, so a "verified" sender
  // on these domains proves nothing about who is behind it.
  var FREEMAIL = ['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
    'yahoo.com', 'ymail.com', 'aol.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com',
    'gmx.com', 'gmx.net', 'mail.com', 'zoho.com', 'yandex.com', 'yandex.ru'];

  // Top-level domains that are cheap to register and frequently abused, or
  // that look like file names (.zip, .mov). Not bad by themselves.
  var RISKY_TLDS = ['zip', 'mov', 'top', 'xyz', 'click', 'icu', 'rest', 'quest',
    'cam', 'cfd', 'sbs', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'support', 'country'];

  // Brands that phishers love to impersonate, with the domains they really use.
  // "label" is the brand's main domain name, used for look-alike detection.
  var BRANDS = [
    { name: 'Microsoft', label: 'microsoft', re: /\b(microsoft|office ?365|microsoft ?365|outlook|onedrive|sharepoint)\b/i,
      token: /micro?s[o0]ft|office365|outlook|onedrive|sharepoint/i,
      domains: ['microsoft.com', 'office.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'office365.com', 'sharepoint.com', 'onedrive.com'] },
    { name: 'PayPal', label: 'paypal', re: /\bpaypal\b/i, token: /payp[a4]l/i, domains: ['paypal.com'] },
    { name: 'Apple', label: 'apple', re: /\b(apple id|apple support|icloud|itunes)\b/i, token: /apple|icloud/i, domains: ['apple.com', 'icloud.com'] },
    { name: 'Amazon', label: 'amazon', re: /\bamazon\b/i, token: /amaz[o0]n/i, domains: ['amazon.com', 'amazon.ca', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazon.com.au', 'amazonses.com'] },
    { name: 'Netflix', label: 'netflix', re: /\bnetflix\b/i, token: /netfl[i1]x/i, domains: ['netflix.com'] },
    { name: 'Google', label: 'google', re: /\bgoogle\b/i, token: /g[o0]{2}gle/i, domains: ['google.com', 'gmail.com', 'youtube.com'] },
    { name: 'DocuSign', label: 'docusign', re: /\bdocusign\b/i, token: /docusign/i, domains: ['docusign.com', 'docusign.net'] },
    { name: 'DoorDash', label: 'doordash', re: /\bdoordash\b/i, token: /d[o0]{2}rdash/i, domains: ['doordash.com'] },
    { name: 'Uber', label: 'uber', re: /\buber( ?eats)?\b/i, token: /\buber/i, domains: ['uber.com', 'ubereats.com'] },
    { name: 'Instacart', label: 'instacart', re: /\binstacart\b/i, token: /instacart/i, domains: ['instacart.com'] },
    { name: 'Walmart', label: 'walmart', re: /\bwalmart\b/i, token: /walmart/i, domains: ['walmart.com', 'walmart.ca'] },
    { name: 'DHL', label: 'dhl', re: /\bDHL\b/, token: /dhl/i, domains: ['dhl.com', 'dhl.ca', 'dhl.co.uk', 'dhl.de'] },
    { name: 'FedEx', label: 'fedex', re: /\bfedex\b/i, token: /fedex/i, domains: ['fedex.com'] },
    { name: 'UPS', label: 'ups', re: /\bUPS\b/, token: /\bups\b/i, domains: ['ups.com'] },
    { name: 'Canada Post', label: 'canadapost', re: /\bcanada post\b/i, token: /canadapost|canada-post/i, domains: ['canadapost.ca', 'canadapost-postescanada.ca'] },
    { name: 'Royal Mail', label: 'royalmail', re: /\broyal mail\b/i, token: /royalmail/i, domains: ['royalmail.com'] },
    { name: 'USPS', label: 'usps', re: /\bUSPS\b/i, token: /usps/i, domains: ['usps.com'] },
    { name: 'Interac', label: 'interac', re: /\binterac\b/i, token: /interac/i, domains: ['interac.ca'] },
    { name: 'CRA', label: 'canada', re: /\b(canada revenue agency|CRA)\b/, token: /\bcra\b/i, domains: ['canada.ca', 'gc.ca'] },
    { name: 'Chase', label: 'chase', re: /\bchase bank\b/i, token: /chase/i, domains: ['chase.com'] },
    { name: 'Wells Fargo', label: 'wellsfargo', re: /\bwells fargo\b/i, token: /wellsfargo/i, domains: ['wellsfargo.com'] },
    { name: 'HMRC', label: 'hmrc', re: /\bHMRC\b/, token: /hmrc/i, domains: ['gov.uk'] },
    { name: 'IRS', label: 'irs', re: /\bIRS\b/, token: /\birs\b/i, domains: ['irs.gov'] }
  ];

  // File extensions that run programs when opened.
  var EXEC_EXT = ['exe', 'scr', 'js', 'jse', 'vbs', 'vbe', 'bat', 'cmd', 'ps1', 'msi',
    'jar', 'hta', 'lnk', 'pif', 'wsf', 'cpl', 'reg', 'dll', 'apk', 'appx', 'msix'];
  // Office files that can contain macros (small programs).
  var MACRO_EXT = ['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'xlam', 'potm', 'ppsm', 'sldm', 'xlsb'];
  // Unusual containers often used to sneak malware or fake login pages past filters.
  var ODD_EXT = ['iso', 'img', 'vhd', 'vhdx', 'zip', 'rar', '7z', 'gz', 'cab', 'html', 'htm', 'shtml', 'svg', 'one'];
  var DOC_EXT = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'jpg', 'jpeg', 'png', 'csv', 'rtf'];

  var MAX_EVIDENCE = 6;

  // ---------------------------------------------------------------------
  // Small helpers
  // ---------------------------------------------------------------------

  // Two-part country domains so "shop.example.co.uk" -> "example.co.uk".
  var SECOND_LEVEL = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'ltd.uk', 'com.au', 'net.au',
    'org.au', 'co.nz', 'co.in', 'co.jp', 'com.br', 'co.za', 'com.sg', 'com.mx', 'gc.ca', 'qc.ca', 'on.ca'];

  function registrableDomain(host) {
    if (!host) return '';
    host = host.toLowerCase().replace(/\.$/, '');
    if (isIP(host)) return host;
    var parts = host.split('.');
    if (parts.length <= 2) return host;
    var lastTwo = parts.slice(-2).join('.');
    if (SECOND_LEVEL.indexOf(lastTwo) !== -1) return parts.slice(-3).join('.');
    return lastTwo;
  }

  function isIP(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || (host.indexOf(':') !== -1 && /^\[?[0-9a-f:]+\]?$/i.test(host));
  }

  function domainIn(domain, list) {
    return list.some(function (d) { return domain === d || domain.slice(-(d.length + 1)) === '.' + d; });
  }

  function isOfficial(domain, brand) { return domainIn(domain, brand.domains); }

  function isTracker(host) { return domainIn(host, TRACKERS); }

  // Is a match inside a "never / do not" sentence? e.g. "We will NEVER ask for
  // your password" should not count as a request for your password.
  function isNegated(text, index) {
    var start = Math.max(0, index - 80);
    var before = text.slice(start, index);
    var cut = Math.max(before.lastIndexOf('.'), before.lastIndexOf('!'), before.lastIndexOf('?'), before.lastIndexOf('\n'));
    if (cut !== -1) before = before.slice(cut + 1);
    return /\b(never|not|don'?t|do not|won'?t|will not|no one|nobody|cannot|can'?t)\b/i.test(before);
  }

  // Run a list of regular expressions over the text and collect matches.
  function findPhrases(text, patterns, opts) {
    opts = opts || {};
    var out = [];
    var seen = {};
    patterns.forEach(function (re) {
      var g = new RegExp(re.source, re.flags.indexOf('g') === -1 ? re.flags + 'g' : re.flags);
      var m;
      while ((m = g.exec(text)) !== null) {
        if (m[0].length === 0) { g.lastIndex++; continue; }
        if (opts.negatable && isNegated(text, m.index)) continue;
        var found = m[0].replace(/\s+$/, '');
        var key = found.toLowerCase().replace(/\s+/g, ' ');
        if (seen[key]) continue;
        seen[key] = true;
        out.push({ text: found, index: m.index, length: found.length });
      }
    });
    out.sort(function (a, b) { return a.index - b.index; });
    return out.slice(0, MAX_EVIDENCE);
  }

  function lastAddress(value) {
    if (!value) return null;
    var all = value.match(/[A-Za-z0-9._%+'=-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g);
    if (!all) return null;
    var addr = all[all.length - 1].toLowerCase();
    return { address: addr, domain: registrableDomain(addr.split('@')[1]) };
  }

  function displayName(value) {
    if (!value) return '';
    var m = /^\s*"?([^"<]*?)"?\s*</.exec(value);
    return m ? m[1].trim() : '';
  }

  // Edit distance between two short strings (used for look-alike domains).
  function editDistance(a, b) {
    var prev = [], cur, i, j;
    for (j = 0; j <= b.length; j++) prev[j] = j;
    for (i = 1; i <= a.length; i++) {
      cur = [i];
      for (j = 1; j <= b.length; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[b.length];
  }

  // Undo the common letter swaps used in fake domains: paypa1 -> paypal, rn -> m.
  function unswap(s) {
    return s.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a')
      .replace(/5/g, 's').replace(/7/g, 't').replace(/rn/g, 'm').replace(/vv/g, 'w');
  }

  // Does this domain imitate a brand without belonging to it?
  function lookalikeOf(domain) {
    if (!domain || isIP(domain)) return null;
    var label = domain.split('.')[0];
    var pieces = [label].concat(label.split('-'));
    for (var i = 0; i < BRANDS.length; i++) {
      var b = BRANDS[i];
      if (isOfficial(domain, b) || b.label.length < 5) continue;
      for (var k = 0; k < pieces.length; k++) {
        var p = pieces[k];
        if (!p || p === b.label) continue;
        if (unswap(p) === b.label) return { brand: b, how: '"' + p + '" swaps letters to imitate "' + b.label + '"' };
        if (p.length >= 6 && Math.abs(p.length - b.label.length) <= 1 && editDistance(p, b.label) === 1) {
          return { brand: b, how: '"' + p + '" is one letter away from "' + b.label + '"' };
        }
      }
    }
    return null;
  }

  // ---------------------------------------------------------------------
  // Step 1: DECODE raw emails into what a person would actually see
  // ---------------------------------------------------------------------

  function bytesToText(binary, charset) {
    try {
      var bytes = new Uint8Array(binary.length);
      for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i) & 255;
      return new TextDecoder((charset || 'utf-8').toLowerCase(), { fatal: false }).decode(bytes);
    } catch (e) {
      try { return new TextDecoder('utf-8').decode(new Uint8Array([].map.call(binary, function (c) { return c.charCodeAt(0) & 255; }))); }
      catch (e2) { return binary; }
    }
  }

  function decodeQP(s, charset) {
    var bin = s.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, function (_, h) { return String.fromCharCode(parseInt(h, 16)); });
    return bytesToText(bin, charset);
  }

  function decodeB64(s, charset) {
    try { return bytesToText(atob(s.replace(/[^A-Za-z0-9+\/=]/g, '')), charset); }
    catch (e) { return s; }
  }

  // "=?UTF-8?Q?Your_order?=" style encoded words in headers.
  function decodeWords(s) {
    return String(s || '').replace(/=\?([^?]+)\?([QqBb])\?([^?]*)\?=\s*/g, function (_, cs, enc, txt) {
      return enc.toUpperCase() === 'B' ? decodeB64(txt, cs) : decodeQP(txt.replace(/_/g, ' '), cs);
    });
  }

  var KNOWN_HEADERS = /^(from|to|cc|subject|date|received|return-path|reply-to|authentication-results|received-spf|delivered-to|message-id|mime-version|content-type|dkim-signature|arc-[\w-]+|x-[\w-]+|sender|list-unsubscribe)$/i;

  // Split "Name: value" header lines (with folded continuation lines) from the body.
  function splitHeaders(raw) {
    var lines = raw.split('\n');
    var headers = [], i = 0, known = false;
    for (; i < lines.length; i++) {
      var line = lines[i];
      if (line === '' ) break;
      if (/^[ \t]/.test(line) && headers.length) {
        headers[headers.length - 1].value += ' ' + line.trim();
        headers[headers.length - 1].raw += '\n' + line;
        continue;
      }
      var m = /^([A-Za-z][A-Za-z0-9-]*):[ \t]?(.*)$/.exec(line);
      if (!m) break;
      if (KNOWN_HEADERS.test(m[1])) known = true;
      headers.push({ name: m[1], lname: m[1].toLowerCase(), value: m[2].trim(), raw: line });
    }
    if (!known) return { headers: [], body: raw };
    return { headers: headers, body: lines.slice(i).join('\n').replace(/^\n/, '') };
  }

  function getHeader(headers, name) {
    for (var i = 0; i < headers.length; i++) if (headers[i].lname === name) return headers[i];
    return null;
  }

  function param(value, key) {
    var m = new RegExp(key + '\\s*=\\s*"?([^";]+)"?', 'i').exec(value || '');
    return m ? m[1].trim() : '';
  }

  // Walk a MIME message and collect its text parts and attachments.
  function walkMime(headers, body, out, depth) {
    var ct = getHeader(headers, 'content-type');
    var type = ct ? ct.value.split(';')[0].trim().toLowerCase() : 'text/plain';
    var enc = (getHeader(headers, 'content-transfer-encoding') || {}).value || '';
    var disp = (getHeader(headers, 'content-disposition') || {}).value || '';
    var charset = param(ct && ct.value, 'charset') || 'utf-8';
    var filename = decodeWords(param(disp, 'filename') || param(ct && ct.value, 'name'));

    if (/^multipart\//.test(type) && depth < 8) {
      var boundary = param(ct.value, 'boundary');
      if (!boundary) return;
      var parts = body.split('--' + boundary);
      for (var i = 1; i < parts.length; i++) {
        var part = parts[i];
        if (/^--/.test(part)) break;
        var p = splitHeaders(part.replace(/^\r?\n/, ''));
        if (!p.headers.length) { p = { headers: [], body: part }; }
        walkMime(p.headers, p.body, out, depth + 1);
      }
      return;
    }
    if (filename || /^attachment/i.test(disp)) {
      out.attachments.push(filename || '(unnamed ' + type + ')');
      return;
    }
    if (type === 'message/rfc822') {
      var inner = splitHeaders(body);
      walkMime(inner.headers, inner.body, out, depth + 1);
      return;
    }
    var text = body;
    if (/quoted-printable/i.test(enc)) text = decodeQP(body, charset);
    else if (/base64/i.test(enc)) text = decodeB64(body, charset);
    if (type === 'text/html') out.html.push(text);
    else if (type === 'text/plain') out.plain.push(text);
  }

  var ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', middot: '·', copy: '©', reg: '®',
    trade: '™', hellip: '…', mdash: '—', ndash: '–', rsquo: '’', lsquo: '‘', rdquo: '”', ldquo: '“', bull: '•', zwnj: '', zwj: '' };

  function decodeEntities(s) {
    return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, function (m, e) {
      if (e[0] === '#') {
        var n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        try { return String.fromCodePoint(n); } catch (x) { return m; }
      }
      var v = ENTITIES[e.toLowerCase()];
      return v === undefined ? m : v;
    });
  }

  // Turn HTML into readable text, remembering every link's shown text and real target.
  function htmlToText(html, anchors) {
    var s = html
      .replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<(style|script|head|title)\b[\s\S]*?<\/\1>/gi, ' ')
      .replace(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi, function (_, attrs, inner) {
        var href = /href\s*=\s*["']([^"']*)["']/i.exec(attrs) || /href\s*=\s*([^\s>]+)/i.exec(attrs);
        var shown = decodeEntities(inner.replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();
        if (href) anchors.push({ href: decodeEntities(href[1]).trim(), shown: shown });
        return ' ' + shown + ' ';
      })
      .replace(/<(br|\/p|\/div|\/tr|\/h[1-6]|\/li|\/table)\b[^>]*>/gi, '\n')
      .replace(/<li\b[^>]*>/gi, '\n• ')
      .replace(/<\/?(b|i|u|em|strong|span|font|small|sup|sub|mark|abbr)\b[^>]*>/gi, '')
      .replace(/<[^>]+>/g, ' ');
    return decodeEntities(s)
      .replace(/[ \t ​-‍͏﻿]+/g, ' ')
      .replace(/ *\n */g, '\n')
      .replace(/\n{3,}/g, '\n\n')
      .trim();
  }

  // Build the clean "message as analysed": key headers + visible body text.
  function prepare(input) {
    var raw = String(input || '').replace(/\r\n?/g, '\n');
    var top = splitHeaders(raw);
    var mime = { plain: [], html: [], attachments: [] };
    var isMime = !!getHeader(top.headers, 'content-type') || !!getHeader(top.headers, 'mime-version');
    if (isMime) walkMime(top.headers, top.body, mime, 0);

    var anchors = [];
    var bodyText;
    if (mime.html.length) bodyText = mime.html.map(function (h) { return htmlToText(h, anchors); }).join('\n\n');
    else if (mime.plain.length) bodyText = mime.plain.join('\n\n').trim();
    else if (/<(html|body|a\s+href|div|table|p)\b/i.test(top.body)) bodyText = htmlToText(top.body, anchors);
    else bodyText = top.body.trim();

    // Keep only the headers that matter for analysis, decoded and on one line each.
    var keep = ['from', 'reply-to', 'return-path', 'subject', 'authentication-results', 'received-spf'];
    var shown = top.headers.filter(function (h) { return keep.indexOf(h.lname) !== -1; });
    var lines = [], headerMap = {}, pos = 0;
    shown.forEach(function (h) {
      var value = h.lname === 'subject' || h.lname === 'from' || h.lname === 'reply-to' ? decodeWords(h.value) : h.value.replace(/\s+/g, ' ');
      var line = h.name + ': ' + value;
      var rec = { name: h.name, value: value, index: pos, length: line.length, valueIndex: pos + h.name.length + 2 };
      (headerMap[h.lname] = headerMap[h.lname] || []).push(rec);
      lines.push(line);
      pos += line.length + 1;
    });
    var headBlock = lines.join('\n');
    var text = headBlock ? headBlock + '\n\n' + bodyText : bodyText;
    var bodyStart = headBlock ? headBlock.length + 2 : 0;

    // Text used for wording rules: the subject and body only. Other header
    // lines are blanked (same length, so highlight positions still line up).
    var scan = text;
    if (headBlock) {
      var masked = lines.map(function (l) { return /^subject:/i.test(l) ? l : l.replace(/[^\n]/g, ' '); }).join('\n');
      scan = masked + text.slice(headBlock.length);
    }

    return {
      text: text, scan: scan, bodyStart: bodyStart, headerMap: headerMap, hasHeaders: lines.length > 0,
      anchors: anchors, mimeAttachments: mime.attachments, decoded: isMime
    };
  }

  // ---------------------------------------------------------------------
  // Step 2: EXTRACT links, attachments, sender and authentication results
  // ---------------------------------------------------------------------

  function parseUrl(raw) {
    try {
      var forParse = raw.replace(/^hxxp/i, 'http');
      if (/^www\./i.test(forParse)) forParse = 'http://' + forParse;
      var u = new URL(forParse);
      if (!/^https?:$/.test(u.protocol)) return null;
      return u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    } catch (e) { return null; }
  }

  function makeUrl(raw, index, sender) {
    var host = parseUrl(raw);
    if (!host) return null;
    var domain = registrableDomain(host);
    return {
      raw: raw, index: index, length: index >= 0 ? raw.length : 0,
      host: host, domain: domain, ip: isIP(host),
      https: /^https:/i.test(raw), explicitHttp: /^(http|hxxp):/i.test(raw), hasAt: /^[a-z]+:\/\/[^\/]*@/i.test(raw),
      ownDomain: !!sender && domain === sender, tracker: isTracker(host)
    };
  }

  function extractUrls(ctx) {
    var re = /\b(?:(?:https?|hxxps?):\/\/|www\.)[^\s<>"'`\]\[{}|\\^]+/gi;
    var out = [], seen = {}, m;
    while ((m = re.exec(ctx.scan)) !== null) {
      var raw = m[0].replace(/[.,;:!?)]+$/, '');
      var key = raw.toLowerCase();
      if (seen[key]) continue;
      var u = makeUrl(raw, m.index, ctx.sender.domain);
      if (!u) continue;
      seen[key] = true;
      out.push(u);
    }
    ctx.anchors.forEach(function (a) {
      var key = a.href.toLowerCase();
      if (seen[key]) return;
      var u = makeUrl(a.href, -1, ctx.sender.domain);
      if (!u) return;
      seen[key] = true;
      var at = a.shown ? ctx.text.indexOf(a.shown, ctx.bodyStart) : -1;
      if (at !== -1) { u.index = at; u.length = a.shown.length; }
      u.shown = a.shown;
      out.push(u);
    });
    return out;
  }

  // Attachment-like file names mentioned in the text, plus real MIME attachments.
  function extractFiles(ctx) {
    var blanked = ctx.scan
      .replace(/\b(?:(?:https?|hxxps?):\/\/|www\.)[^\s<>"']+/gi, function (s) { return ' '.repeat(s.length); })
      .replace(/[A-Za-z0-9._%+=-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, function (s) { return ' '.repeat(s.length); });
    var all = EXEC_EXT.concat(MACRO_EXT, ODD_EXT);
    var re = new RegExp('(?:^|[\\s"\'(\\[:])([A-Za-z0-9][A-Za-z0-9_\\-]{0,60}?(?:\\.[A-Za-z0-9]{2,5})*\\.(' + all.join('|') + '))(?=$|[\\s"\'),.;:\\]])', 'gim');
    var out = [], seen = {}, m;
    function add(name, index) {
      var key = name.toLowerCase();
      if (seen[key]) return;
      seen[key] = true;
      var parts = key.split('.');
      var ext = parts.length > 1 ? parts[parts.length - 1] : '';
      var prev = parts.length > 2 ? parts[parts.length - 2] : '';
      out.push({ name: name, index: index, length: index >= 0 ? name.length : 0, ext: ext, doubleExt: DOC_EXT.indexOf(prev) !== -1 });
    }
    while ((m = re.exec(blanked)) !== null) add(m[1].trim(), m.index + m[0].indexOf(m[1]));
    ctx.mimeAttachments.forEach(function (n) { add(n, ctx.text.indexOf(n)); });
    return out;
  }

  // Read SPF / DKIM / DMARC results and check they belong to the From domain.
  function readAuth(ctx) {
    var res = { found: false, spf: null, dkim: null, dmarc: null, spfAligned: false, dkimAligned: false, dmarcAligned: false, records: [] };
    var from = ctx.sender.domain;
    (ctx.headerMap['authentication-results'] || []).forEach(function (h) {
      res.found = true;
      res.records.push(h);
      var v = h.value, m;
      var reSpf = /\bspf=(\w+)/gi, reDkim = /\bdkim=(\w+)([^;]*)/gi, reDmarc = /\bdmarc=(\w+)([^;]*)/gi;
      while ((m = reSpf.exec(v))) {
        var r = m[1].toLowerCase();
        if (r === 'pass' || !res.spf || res.spf === 'none') res.spf = res.spf === 'pass' ? 'pass' : r;
        var mf = /smtp\.mailfrom=["<]?(?:[^@\s;"<>]*@)?([A-Za-z0-9.-]+)/i.exec(v);
        if (r === 'pass' && mf && registrableDomain(mf[1]) === from) res.spfAligned = true;
      }
      while ((m = reDkim.exec(v))) {
        var d = m[1].toLowerCase();
        if (d === 'pass' || !res.dkim || res.dkim === 'none') res.dkim = res.dkim === 'pass' ? 'pass' : d;
        var dom = /header\.(?:i=@?|d=)([A-Za-z0-9.-]+)/i.exec(m[2]);
        if (d === 'pass' && dom && registrableDomain(dom[1]) === from) res.dkimAligned = true;
      }
      while ((m = reDmarc.exec(v))) {
        var dm = m[1].toLowerCase();
        if (dm === 'pass' || !res.dmarc) res.dmarc = res.dmarc === 'pass' ? 'pass' : dm;
        var hf = /header\.from=([A-Za-z0-9.-]+)/i.exec(m[2]);
        if (dm === 'pass' && (!hf || registrableDomain(hf[1]) === from)) res.dmarcAligned = true;
      }
    });
    (ctx.headerMap['received-spf'] || []).forEach(function (h) {
      res.found = true;
      var r = (h.value.split(/[\s(]/)[0] || '').toLowerCase();
      if (!res.spf || (res.spf !== 'pass' && r === 'pass')) res.spf = r;
      res.records.push(h);
    });
    res.verified = !!from && res.dmarcAligned && !ctx.sender.free && !ctx.sender.lookalike;
    return res;
  }

  // ---------------------------------------------------------------------
  // Step 3: THE RULES. Each one is a single, explainable sign.
  //   points  - exactly how much this sign adds (or, if negative, removes)
  //   danger  - true for a "dangerous ask" or forged sender (see step 4)
  //   why     - plain-English reason it matters (shown to the user)
  //   detect  - returns a list of evidence; an empty list means "not found"
  // ---------------------------------------------------------------------
  var RULES = [
    {
      id: 'urgency', name: 'Urgency and pressure language', category: 'Social engineering', points: 10,
      why: 'Attackers rush you so you act before you think. Real organisations rarely demand action within minutes or hours.',
      detect: function (c) {
        return findPhrases(c.scan, [
          /\burgent(ly)?\b/i, /\bimmediate(ly)?\b/i, /\bright away\b/i,
          /\bwithin (the next )?\d+ ?(hours?|hrs?|minutes?|mins?)\b/i, /\b(final|last) (notice|warning|reminder)\b/i,
          /\btime[- ]sensitive\b/i, /\bas soon as possible\b/i, /\bdo not (delay|ignore)\b/i,
          /\bfailure to (respond|act|comply|verify|confirm|pay)\b/i, /\bbefore (it'?s too late|end of (the )?day)\b/i, /\basap\b/i
        ]);
      }
    },
    {
      id: 'promo', name: 'Sales-style urgency', category: 'Social engineering', points: 3,
      why: 'Phrases like "offer ends today" are normal in marketing, so they only count a little. They matter more when combined with a request for details or money.',
      detect: function (c) {
        return findPhrases(c.scan, [
          /\b(offer|deal|sale|discount|promo(tion)?|savings?|code) (ends|expires)\b/i, /\bexpires? (today|tonight|soon|in \d+)/i,
          /\blimited[- ]time\b/i, /\btoday only\b/i, /\blast chance\b/i, /\bact now\b/i, /\bhurry\b/i, /\bdon'?t miss (out)?\b/i
        ]);
      }
    },
    {
      id: 'threat', name: 'Threat of account suspension or closure', category: 'Social engineering', points: 15,
      why: 'Threatening to lock, suspend or delete your account creates fear, which is a classic way to make people hand over details.',
      detect: function (c) {
        return findPhrases(c.scan, [
          /\b(account|mailbox|access|service|subscription|profile)s? (has been|have been|will be|is being|may be) (suspended|locked|closed|disabled|deactivated|terminated|restricted|deleted|blocked|limited)\b/i,
          /\b(suspend|suspension of|close|closure of|deactivate|terminate|disable|restrict) (your|the) (account|mailbox|access|service)/i,
          /\bpermanently (deleted|disabled|closed|locked|removed)\b/i, /\b(will|may) (lose|be unable to) access\b/i,
          /\blegal action\b/i, /\b(arrest|warrant)\b/i
        ], { negatable: true });
      }
    },
    {
      id: 'password', name: 'Request for your password', category: 'Credential theft', points: 25, danger: true,
      why: 'Legitimate organisations never ask you to send or "confirm" your password by email or through a link in an email.',
      detect: function (c) {
        return findPhrases(c.scan, [
          /\b(enter|confirm|verify|provide|update|re-?enter|send|submit|reply with|type|validate|re-?validate|keep)( us)? (your |the )?(current |existing |email |account |login )?(password|passcode|passphrase|login credentials|credentials|pin)\b/i,
          /\b(password|login credentials|credentials) (is|are) required\b/i,
          /\busername and password\b/i
        ], { negatable: true });
      }
    },
    {
      id: 'mfa', name: 'Request for an MFA or verification code', category: 'Credential theft', points: 25, danger: true,
      why: 'One-time codes prove that YOU are logging in. Anyone who asks you to share one is probably trying to log in as you right now.',
      detect: function (c) {
        return findPhrases(c.scan, [
          /\b(share|send|provide|reply with|enter|tell us|read (out|back)|forward|give us|confirm)( us)? (the |your |this )?(\d-digit |six-digit |one[- ]time )?(verification|security|authentication|authenticator|access|sms|2fa|mfa|otp|one[- ]time|login|confirmation) (code|pin|passcode)s?\b/i,
          /\b(send|forward|share|reply with) (us )?(the )?code (we|that was|you) (sent|received|get)/i
        ], { negatable: true });
      }
    },
    {
      id: 'harvest', name: 'Credential-harvesting language', category: 'Credential theft', points: 20, danger: true,
      why: 'Phrases like "verify your account" or "confirm your identity" usually lead to a fake login page built to steal what you type.',
      detect: function (c) {
        return findPhrases(c.scan, [
          /\b(verify|confirm|validate|restore|unlock|reactivate|re-?activate) (your )?(account|identity|login|mailbox|email address|details|information|billing|payment (details|method|information))\b/i,
          /\b(log ?in|sign ?in|click (here|below|the (link|button)))( now)? to (verify|confirm|restore|keep|avoid|unlock|validate|secure|reactivate)\b/i,
          /\bunusual (sign[- ]in|login) activity\b/i, /\bsuspicious (sign[- ]in|login) activity\b/i,
          /\bkeep (my |your )?(current )?password\b/i, /\bpassword (expires|will expire|has expired)\b/i
        ], { negatable: true });
      }
    },
    {
      id: 'giftcard', name: 'Gift card, cryptocurrency or untraceable payment request', category: 'Financial fraud', points: 25, danger: true,
      why: 'Gift cards, crypto and wire transfers are almost impossible to reverse, which is exactly why scammers ask for them.',
      detect: function (c) {
        return findPhrases(c.scan, [
          /\b(buy|purchase|get|send|pick up) .{0,30}\b(gift|itunes|apple|google play|steam|amazon|ebay|vanilla) ?cards?\b/i,
          /\bscratch (off )?the (back|code)/i, /\b(photo|picture|pic)s? of the (cards?|codes?)\b/i,
          /\b(bitcoin|btc|ethereum|usdt|crypto(currency)?) (wallet|address|payment|transfer)\b/i,
          /\b(pay|send|transfer) .{0,20}\b(in|via|using) (bitcoin|crypto|btc)\b/i, /\bwestern union\b/i, /\bmoneygram\b/i
        ]);
      }
    },
    {
      id: 'payment', name: 'Request to pay a fee or balance', category: 'Financial fraud', points: 10, danger: true,
      why: 'A message asking you to pay, even a small "fee", is a common trick. Small amounts lower your guard and capture your card details.',
      detect: function (c) {
        return findPhrases(c.scan, [
          /\b(pay|settle|clear) (the |a |an |your )?(outstanding|overdue|small|redelivery|customs|shipping|processing|unpaid|remaining)? ?(balance|fee|amount|charge|invoice|payment|duty|dues)\b/i,
          /\b(redelivery|customs|handling|release|reactivation|unlock) (fee|charge|duty)\b/i,
          /\b(wire|bank) transfer\b/i, /\bprocess (the|a|this) (payment|transfer)\b/i, /\bpayment (is )?(required|needed|overdue)\b/i
        ], { negatable: true });
      }
    },
    {
      id: 'bankchange', name: 'Request to change bank or payment details', category: 'Financial fraud', points: 25, danger: true,
      why: 'Changing where money is paid is the heart of Business Email Compromise (BEC) fraud. Always confirm by phone using a number you already know.',
      detect: function (c) {
        return findPhrases(c.scan, [
          /\b(new|updated|changed|change (of|to|our|in)|update (to )?our|different) (bank(ing)?|remittance|payroll|direct deposit) ?(details|information|info|account|instructions)?\b/i,
          /\b(bank(ing)?|payment|account) (details|information|instructions) (have|has) (changed|been updated)\b/i,
          /\b(iban|swift code|sort code|routing number)\b/i,
          /\bdo not (use|pay (to|into)) (the|our) (old|previous)\b/i
        ]);
      }
    },
    {
      id: 'impersonation', name: 'Possible brand impersonation', category: 'Impersonation', points: 15, danger: true,
      why: 'The sender presents itself as a well-known brand, but the sender address or the links use a domain that brand does not own.',
      detect: function (c) {
        var out = [];
        var from = c.sender.domain;
        var domains = c.urls.filter(function (u) { return !u.tracker; }).map(function (u) { return u.domain; });
        if (from) domains.push(from);
        if (!domains.length) return out;
        // With headers we look at who the email CLAIMS to be (name + subject);
        // without headers we can only look at the body.
        var claim = c.hasHeaders
          ? [c.sender.name, c.subject.value].join(' \n ')
          : c.scan;
        BRANDS.forEach(function (b) {
          var m = b.re.exec(claim);
          if (!m) return;
          if (from ? isOfficial(from, b) : domains.some(function (d) { return isOfficial(d, b); })) return;
          var where = from ? 'the sender ' + c.sender.address : 'the links';
          var idx = c.text.indexOf(m[0]);
          out.push({ text: m[0], index: idx, length: idx >= 0 ? m[0].length : 0,
            note: 'Claims to be ' + b.name + ', but ' + where + ' does not use an official ' + b.name + ' domain (' + b.domains[0] + ')' });
        });
        return out.slice(0, MAX_EVIDENCE);
      }
    },
    {
      id: 'lookalike', name: 'Look-alike domain', category: 'Impersonation', points: 30, danger: true,
      why: 'The domain imitates a real brand by swapping letters (paypa1, rnicrosoft) or adding one, hoping you will not notice.',
      detect: function (c) {
        var out = [], seen = {};
        var list = [];
        if (c.sender.domain) list.push({ d: c.sender.domain, idx: c.from ? c.from.valueIndex : -1, len: c.from ? c.from.value.length : 0, what: 'Sender domain' });
        if (c.replyTo) { var r = lastAddress(c.replyTo.value); if (r) list.push({ d: r.domain, idx: c.replyTo.valueIndex, len: c.replyTo.value.length, what: 'Reply-To domain' }); }
        c.urls.forEach(function (u) { list.push({ d: u.domain, idx: u.index, len: u.length, what: 'Link domain' }); });
        list.forEach(function (x) {
          if (seen[x.d]) return;
          var hit = lookalikeOf(x.d);
          if (!hit) return;
          seen[x.d] = true;
          out.push({ text: x.d, index: x.idx, length: x.len, note: x.what + ' ' + x.d + ': ' + hit.how + ' (real: ' + hit.brand.domains[0] + ')' });
        });
        return out.slice(0, MAX_EVIDENCE);
      }
    },
    {
      id: 'greeting', name: 'Generic greeting', category: 'Impersonation', points: 5,
      why: 'Companies you have accounts with usually know your name. "Dear Customer" suggests a mass message sent to many people.',
      detect: function (c) {
        return findPhrases(c.scan, [
          /\bdear (valued )?(customer|user|client|member|account holder|sir\/madam|sir or madam|beneficiary|recipient|employee|staff)\b/i,
          /\bhello (user|customer|dear)\b/i
        ]);
      }
    },
    {
      id: 'secrecy', name: 'Secrecy or authority pressure', category: 'Social engineering', points: 10,
      why: 'Asking you to keep something secret, or saying the boss cannot be reached, stops you from checking with anyone. This is common in CEO fraud.',
      detect: function (c) {
        return findPhrases(c.scan, [
          /\bkeep (this|it) (confidential|private|between us|quiet|to yourself)\b/i, /\b(strictly|highly) confidential\b/i,
          /\b(do not|don'?t) (tell|discuss|mention|share this with) (anyone|others|colleagues)\b/i,
          /\b(i'?m|i am) (in a meeting|travel(l)?ing|on a flight|unavailable|not reachable)\b/i,
          /\b(can'?t|cannot|unable to) (take|answer) (calls|the phone|a call)\b/i, /\bare you (at your desk|available)\b/i
        ]);
      }
    },
    {
      id: 'invoice', name: 'Unexpected invoice or payment language', category: 'Financial fraud', points: 5,
      why: 'Fake invoices and "overdue" notices are a favourite lure. Receipts are normal, so this only counts a little unless combined with other signs.',
      detect: function (c) {
        return findPhrases(c.scan, [
          /\binvoice\b/i, /\boverdue\b/i, /\boutstanding (balance|amount|payment|invoice)\b/i, /\bremittance\b/i,
          /\bpurchase order\b/i, /\bpayment (due|reminder|overdue)\b/i, /\bunpaid\b/i, /\bproforma\b/i
        ]);
      }
    },
    {
      id: 'ipurl', name: 'Link uses a raw IP address', category: 'Suspicious links', points: 20, danger: true,
      why: 'Real companies link to named websites, not to a bare number like 192.0.2.10. A raw IP address often means a temporary or hacked server.',
      detect: function (c) {
        return c.urls.filter(function (u) { return u.ip; }).slice(0, MAX_EVIDENCE)
          .map(function (u) { return { text: u.raw, index: u.index, length: u.length, note: 'Points directly at ' + u.host }; });
      }
    },
    {
      id: 'shorturl', name: 'Shortened link hides the destination', category: 'Suspicious links', points: 15,
      why: 'Link shorteners hide where a link really goes. Legitimate security emails from big companies almost never use them.',
      detect: function (c) {
        return c.urls.filter(function (u) { return domainIn(u.host, SHORTENERS); }).slice(0, MAX_EVIDENCE)
          .map(function (u) { return { text: u.raw, index: u.index, length: u.length, note: 'Uses the shortening service ' + u.host }; });
      }
    },
    {
      id: 'badurl', name: 'Suspicious-looking link', category: 'Suspicious links', points: 15,
      why: 'Fake sites often put a brand name or words like "login" and "secure" into an unrelated domain, so that a quick glance looks convincing.',
      detect: function (c) {
        var out = [];
        c.urls.forEach(function (u) {
          if (u.ip || u.tracker || (u.ownDomain && c.auth.verified)) return;
          var traits = [];
          var tld = u.host.split('.').pop();
          if (/xn--/.test(u.host)) traits.push('uses "xn--" encoding, which can disguise look-alike letters');
          if (u.hasAt) traits.push('contains "@", which hides the real destination after it');
          if (RISKY_TLDS.indexOf(tld) !== -1) traits.push('ends in ".' + tld + '", a domain ending often abused');
          if (u.explicitHttp && /log ?in|sign ?in|verify|account|secure|password|bank/i.test(u.raw)) traits.push('asks for sensitive actions without encryption (http, not https)');
          BRANDS.forEach(function (b) {
            if (b.token.test(u.host) && !isOfficial(u.domain, b)) traits.push('contains "' + b.name + '" but the real domain is ' + u.domain);
          });
          if (!u.ownDomain && /(log-?in|sign-?in|verify|verification|secure|account|update|auth|wallet)/i.test(u.domain.split('.')[0]) && traits.length === 0)
            traits.push('the domain name itself (' + u.domain + ') uses security words to look official');
          if (u.host.split('.').length >= 6) traits.push('has an unusually long chain of sub-domains');
          if ((u.host.match(/-/g) || []).length >= 4) traits.push('has many hyphens in the domain');
          if (traits.length) out.push({ text: u.shown || u.raw, index: u.index, length: u.length, note: (u.shown ? u.raw + ': ' : '') + traits.join('; ') });
        });
        return out.slice(0, MAX_EVIDENCE);
      }
    },
    {
      id: 'misleading', name: 'Misleading link text', category: 'Suspicious links', points: 20, danger: true,
      why: 'The text you see shows one web address, but clicking would take you somewhere completely different.',
      detect: function (c) { return findMisleadingLinks(c); }
    },
    {
      id: 'execfile', name: 'Executable attachment type', category: 'Attachments', points: 30, danger: true,
      why: 'These file types run programs on your computer when opened. They are one of the most common ways malware is delivered.',
      detect: function (c) {
        return c.files.filter(function (f) { return EXEC_EXT.indexOf(f.ext) !== -1; }).slice(0, MAX_EVIDENCE)
          .map(function (f) { return { text: f.name, index: f.index, length: f.length, note: '".' + f.ext + '" files can run code' }; });
      }
    },
    {
      id: 'macrofile', name: 'Macro-enabled Office file', category: 'Attachments', points: 15, danger: true,
      why: 'Office files ending in "m" (like .docm or .xlsm) can contain macros: small programs that attackers use to install malware.',
      detect: function (c) {
        return c.files.filter(function (f) { return MACRO_EXT.indexOf(f.ext) !== -1; }).slice(0, MAX_EVIDENCE)
          .map(function (f) { return { text: f.name, index: f.index, length: f.length, note: '".' + f.ext + '" can contain macros' }; });
      }
    },
    {
      id: 'oddfile', name: 'Unusual attachment filename', category: 'Attachments', points: 15, danger: true,
      why: 'Double extensions (invoice.pdf.exe), disk images, archives and HTML files are used to slip past filters or open fake login pages.',
      detect: function (c) {
        return c.files.filter(function (f) { return f.doubleExt || ODD_EXT.indexOf(f.ext) !== -1; }).slice(0, MAX_EVIDENCE)
          .map(function (f) {
            return { text: f.name, index: f.index, length: f.length,
              note: f.doubleExt ? 'Double extension: looks like a document but is really ".' + f.ext + '"' : '".' + f.ext + '" is an unusual attachment type' };
          });
      }
    },
    {
      id: 'macros', name: 'Asks you to enable macros or editing', category: 'Attachments', points: 25, danger: true,
      why: 'Office blocks macros for safety. Asking you to "Enable Content" is how attackers switch that protection off.',
      detect: function (c) {
        return findPhrases(c.scan, [
          /\benable (the )?(macros?|content|editing|active content)\b/i, /\bclick ["']?enable\b/i,
          /\ballow (the )?macros?\b/i, /\bturn on macros?\b/i
        ]);
      }
    },
    {
      id: 'replyto', name: 'Sender and Reply-To do not match', category: 'Email headers', points: 20, danger: true,
      why: 'Replies would go to a different organisation than the one the email claims to be from. Attackers do this so your answer reaches them.',
      detect: function (c) {
        var r = c.replyTo && lastAddress(c.replyTo.value);
        if (!c.sender.domain || !r || r.domain === c.sender.domain || isTracker(r.domain)) return [];
        return [{ text: c.replyTo.value, index: c.replyTo.index, length: c.replyTo.length,
          note: 'From uses ' + c.sender.domain + ' but replies go to ' + r.domain }];
      }
    },
    {
      id: 'returnpath', name: 'Return-Path differs from sender', category: 'Email headers', points: 5,
      why: 'The technical bounce address belongs to a different domain. Mailing services do this legitimately, so it is only a weak signal.',
      detect: function (c) {
        var rp = c.headerMap['return-path'] && c.headerMap['return-path'][0];
        var r = rp && lastAddress(rp.value);
        if (!c.sender.domain || !r || r.domain === c.sender.domain || c.auth.verified || isTracker(r.domain)) return [];
        return [{ text: rp.value, index: rp.index, length: rp.length, note: 'From uses ' + c.sender.domain + ' but Return-Path uses ' + r.domain }];
      }
    },
    {
      id: 'spf', name: 'SPF check failed', category: 'Email authentication', points: 15, danger: true,
      why: 'SPF lets a domain list which servers may send its mail. A failure means this email came from a server the domain did not approve.',
      detect: function (c) { return /^(fail|softfail|permerror)$/.test(c.auth.spf || '') ? authEvidence(c, /\bspf=(fail|softfail|permerror)\b|^Received-SPF: *(fail|softfail|permerror)\b/i, 'spf=' + c.auth.spf) : []; }
    },
    {
      id: 'dkim', name: 'DKIM check failed', category: 'Email authentication', points: 15, danger: true,
      why: 'DKIM is a digital signature on the email. A failure means the signature was broken or the message was changed in transit.',
      detect: function (c) { return /^(fail|permerror)$/.test(c.auth.dkim || '') ? authEvidence(c, /\bdkim=(fail|permerror)\b/i, 'dkim=' + c.auth.dkim) : []; }
    },
    {
      id: 'dmarc', name: 'DMARC check failed', category: 'Email authentication', points: 20, danger: true,
      why: 'DMARC checks that the "From" domain you see is backed up by SPF or DKIM. A failure is a strong sign the sender address is forged.',
      detect: function (c) { return /^(fail|permerror)$/.test(c.auth.dmarc || '') ? authEvidence(c, /\bdmarc=(fail|permerror)\b/i, 'dmarc=' + c.auth.dmarc) : []; }
    },

    // ----- Reassuring signs: these take points AWAY -----
    {
      id: 'dmarcpass', name: 'DMARC passed for the sender\'s domain', category: 'Verified sender', points: -15, trust: true,
      why: 'The receiving mail server confirmed this email really came from the domain shown in "From". It proves where it came from, not that the sender is honest.',
      detect: function (c) { return c.auth.verified ? authEvidence(c, /\bdmarc=pass\b/i, 'dmarc=pass for ' + c.sender.domain) : []; }
    },
    {
      id: 'dkimpass', name: 'DKIM signature matches the sender', category: 'Verified sender', points: -10, trust: true,
      why: 'The email carries a valid digital signature from the same domain shown in "From", so it was not changed on the way.',
      detect: function (c) { return c.auth.verified && c.auth.dkimAligned ? authEvidence(c, /\bdkim=pass\b/i, 'dkim=pass signed by ' + c.sender.domain) : []; }
    },
    {
      id: 'spfpass', name: 'SPF passed for the sender\'s domain', category: 'Verified sender', points: -5, trust: true,
      why: 'The server that sent this email is on the approved list for the sender\'s own domain.',
      detect: function (c) { return c.auth.verified && c.auth.spfAligned ? authEvidence(c, /\bspf=pass\b/i, 'spf=pass for ' + c.sender.domain) : []; }
    }
  ];

  function authEvidence(c, re, note) {
    for (var i = 0; i < c.auth.records.length; i++) {
      var h = c.auth.records[i];
      var line = h.name + ': ' + h.value;
      var m = re.exec(line);
      if (m) return [{ text: m[0], index: h.index + m.index, length: m[0].length, note: note }];
    }
    return [{ text: note, index: -1, length: 0, note: note }];
  }

  // Link text that shows one address while the real link goes somewhere else.
  function findMisleadingLinks(c) {
    var out = [];
    var domainInText = /^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[\/?#:]|$)/i;

    function check(shown, target, index, length) {
      var dm = domainInText.exec(String(shown || '').trim());
      if (!dm) return;
      var shownDom = registrableDomain(dm[1]);
      var targetHost = parseUrl(target);
      if (!targetHost) return;
      var targetDom = registrableDomain(targetHost);
      if (shownDom === targetDom) return;
      // A verified sender sending its own address through a click-tracking
      // service (or its own sub-domain) is normal marketing practice.
      if (c.auth.verified && shownDom === c.sender.domain && (isTracker(targetHost) || targetDom === c.sender.domain)) return;
      out.push({ text: shown, index: index, length: length, note: 'Shows "' + dm[1] + '" but actually goes to "' + targetHost + '"' });
    }

    c.urls.forEach(function (u) { if (u.shown) check(u.shown, u.raw, u.index, u.length); });
    var m;
    var md = /\[([^\]]+)\]\(((?:https?|hxxps?):\/\/[^)\s]+)\)/gi;
    while ((m = md.exec(c.scan)) !== null) check(m[1], m[2], m.index, m[0].length);
    var plain = /((?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}[^\s<]*)\s?<((?:https?|hxxps?):\/\/[^>\s]+)>/gi;
    while ((m = plain.exec(c.scan)) !== null) check(m[1], m[2], m.index, m[0].length);
    return out.slice(0, MAX_EVIDENCE);
  }

  // ---------------------------------------------------------------------
  // Recommendations, chosen based on which signs were found
  // ---------------------------------------------------------------------
  function recommendations(found, band, ctx) {
    var ids = {};
    found.forEach(function (f) { ids[f.id] = true; });
    var recs = [];
    if (band.level !== 'low') recs.push('Do not click any links, open any attachments, or reply to this message.');
    if (ids.password || ids.harvest || ids.mfa) {
      recs.push('If you already typed a password on a page from this email, change it straight away from the official website or app (type the address yourself), and change it anywhere else you reused it.');
    }
    if (ids.mfa) recs.push('Never share a one-time or verification code with anyone. If you already did, contact the organisation\'s official support immediately and review your account sign-in activity.');
    if (ids.bankchange || ids.payment || ids.giftcard) recs.push('Before paying anything or changing any payment details, call the person or company on a phone number you already have on file, not one from this email.');
    if (ids.giftcard) recs.push('No genuine business or manager pays bills with gift cards or cryptocurrency. Treat this as a scam.');
    if (ids.execfile || ids.macrofile || ids.oddfile || ids.macros) {
      recs.push('Do not open the attachment, and never click "Enable Content" or "Enable Macros". If you opened it, disconnect from the network and contact your IT or security team.');
    }
    if (ids.lookalike) recs.push('Look closely at the domain: it imitates a real brand. Go to the real website by typing its address yourself.');
    if (ids.impersonation || ids.replyto || ids.dmarc || ids.spf || ids.dkim) {
      recs.push('Check the real sender: go to the organisation\'s official website or app by typing the address yourself, and look for the same message there.');
    }
    if (band.level !== 'low') {
      recs.push('Report the message using your email app\'s "Report phishing" button, or forward it to your IT/security team, then delete it.');
    } else {
      if (ctx.auth.verified) recs.push('The sender\'s domain (' + ctx.sender.domain + ') was verified. Make sure that is really the company you expect, as scammers can verify look-alike domains too.');
      recs.push('For anything involving your account, money or personal details, use the organisation\'s official app or website rather than links in the email.');
      recs.push('Low risk is not the same as safe. If something feels off, trust your instinct and verify first.');
    }
    return recs;
  }

  // ---------------------------------------------------------------------
  // Main entry point
  // ---------------------------------------------------------------------
  function analyse(input) {
    var p = prepare(input);
    var fromH = p.headerMap.from && p.headerMap.from[0];
    var addr = fromH ? lastAddress(fromH.value) : null;
    var ctx = {
      text: p.text, scan: p.scan, bodyStart: p.bodyStart, headerMap: p.headerMap, hasHeaders: p.hasHeaders,
      anchors: p.anchors, mimeAttachments: p.mimeAttachments,
      from: fromH || null,
      replyTo: p.headerMap['reply-to'] ? p.headerMap['reply-to'][0] : null,
      subject: p.headerMap.subject ? p.headerMap.subject[0] : { value: '' },
      sender: {
        address: addr ? addr.address : '', domain: addr ? addr.domain : '',
        name: fromH ? displayName(fromH.value) : '',
        free: addr ? FREEMAIL.indexOf(addr.domain) !== -1 : false,
        lookalike: addr ? !!lookalikeOf(addr.domain) : false
      }
    };
    ctx.auth = readAuth(ctx);
    ctx.urls = extractUrls(ctx);
    ctx.files = extractFiles(ctx);

    var risks = [], trust = [];
    RULES.forEach(function (rule) {
      var evidence = rule.detect(ctx) || [];
      if (!evidence.length) return;
      var item = { id: rule.id, name: rule.name, category: rule.category, points: rule.points, why: rule.why, danger: !!rule.danger, evidence: evidence };
      (rule.trust ? trust : risks).push(item);
    });

    // Step 4: CONTEXT
    var riskTotal = risks.reduce(function (s, f) { return s + f.points; }, 0);
    var trustTotal = trust.reduce(function (s, f) { return s + f.points; }, 0);
    var hasDanger = risks.some(function (f) { return f.danger; });
    // A verified sender proves WHO sent it, not that a risky request is safe
    // (accounts get hacked, and scammers verify their own domains too). So
    // when there is a dangerous request, reassuring signs do not count.
    var trustLimited = hasDanger && trustTotal < TRUST_LIMIT_WITH_DANGER;
    if (trustLimited) trustTotal = TRUST_LIMIT_WITH_DANGER;
    var rawTotal = riskTotal + trustTotal;
    var cap = null;
    if (!hasDanger && ctx.auth.verified && rawTotal > CAP_VERIFIED_NO_DANGER) {
      cap = { limit: CAP_VERIFIED_NO_DANGER, reason: 'Verified sender and no dangerous request (no password, code, payment, risky attachment or forged sender), so the score stays in Low Risk.' };
    } else if (!hasDanger && rawTotal > CAP_NO_DANGER) {
      cap = { limit: CAP_NO_DANGER, reason: 'No dangerous request was found (no password, code, payment, risky attachment or forged sender), so the score cannot reach High Risk.' };
    }
    var score = Math.max(0, Math.min(100, cap ? cap.limit : rawTotal));
    var band = BANDS.filter(function (b) { return score >= b.min; })[0];

    return {
      score: score,
      riskTotal: riskTotal,
      trustTotal: trustTotal,
      trustLimited: trustLimited,
      rawTotal: rawTotal,
      cap: cap,
      band: band,
      indicators: risks,
      trust: trust,
      recommendations: recommendations(risks, band, ctx),
      analysedText: p.text,
      stats: {
        links: ctx.urls.length,
        attachments: ctx.files.length,
        headersFound: ctx.hasHeaders,
        decoded: p.decoded,
        authFound: ctx.auth.found,
        sender: ctx.sender.domain,
        verified: ctx.auth.verified,
        auth: { spf: ctx.auth.spf, dkim: ctx.auth.dkim, dmarc: ctx.auth.dmarc }
      }
    };
  }

  var api = { analyse: analyse, RULES: RULES, BANDS: BANDS, CAPS: { noDanger: CAP_NO_DANGER, verifiedNoDanger: CAP_VERIFIED_NO_DANGER, trustWithDanger: TRUST_LIMIT_WITH_DANGER } };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else global.PhishAnalyser = api;
})(this);
