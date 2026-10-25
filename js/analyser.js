/*
 * Phishing Email Analyser - the analysis engine.
 *
 * Everything in this file runs inside your own web browser. Nothing is ever
 * sent anywhere: there are no network calls in this project at all.
 *
 * How it works, in plain English:
 *   1. We read the pasted email as plain text (we never open links or files).
 *   2. We pull out useful pieces: links, email headers, attachment names.
 *   3. We run a list of RULES. Each rule looks for one warning sign.
 *   4. Every rule that matches adds its FIXED number of points to the score.
 *   5. The total is capped at 100 and turned into Low / Suspicious / High.
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
      summary: 'Few or no common warning signs were found. That does not prove the message is safe; skilled attackers can avoid every pattern this tool checks.' }
  ];

  // Well-known URL shortening services. A short link hides the real destination.
  var SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 't.ly',
    'bl.ink', 'lnkd.in', 's.id', 'v.gd', 'qrco.de', 'shorte.st', 'adf.ly'
  ];

  // Top-level domains that are cheap to register and frequently abused, or
  // that look like file names (.zip, .mov). Not bad by themselves.
  var RISKY_TLDS = ['zip', 'mov', 'top', 'xyz', 'click', 'icu', 'rest', 'quest',
    'cam', 'cfd', 'sbs', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'support', 'country'];

  // Brands that phishers love to impersonate, with the domains they really use.
  var BRANDS = [
    { name: 'Microsoft', re: /\b(microsoft|office ?365|microsoft ?365|outlook|onedrive|sharepoint|teams)\b/i,
      token: /micro?s[o0]ft|office365|outlook|onedrive|sharepoint/i,
      domains: ['microsoft.com', 'office.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'office365.com', 'sharepoint.com', 'onedrive.com'] },
    { name: 'PayPal', re: /\bpaypal\b/i, token: /payp[a4]l/i, domains: ['paypal.com'] },
    { name: 'Apple', re: /\b(apple id|apple support|icloud|itunes)\b/i, token: /apple|icloud/i, domains: ['apple.com', 'icloud.com'] },
    { name: 'Amazon', re: /\bamazon\b/i, token: /amaz[o0]n/i, domains: ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazon.ca', 'amazon.com.au'] },
    { name: 'Netflix', re: /\bnetflix\b/i, token: /netfl[i1]x/i, domains: ['netflix.com'] },
    { name: 'Google', re: /\b(google|gmail)\b/i, token: /g[o0]{2}gle|gmail/i, domains: ['google.com', 'gmail.com'] },
    { name: 'DocuSign', re: /\bdocusign\b/i, token: /docusign/i, domains: ['docusign.com', 'docusign.net'] },
    { name: 'DHL', re: /\bDHL\b/, token: /dhl/i, domains: ['dhl.com', 'dhl.co.uk', 'dhl.de'] },
    { name: 'FedEx', re: /\bfedex\b/i, token: /fedex/i, domains: ['fedex.com'] },
    { name: 'UPS', re: /\bUPS\b/, token: /\bups\b/i, domains: ['ups.com'] },
    { name: 'Royal Mail', re: /\broyal mail\b/i, token: /royalmail/i, domains: ['royalmail.com'] },
    { name: 'USPS', re: /\bUSPS\b/i, token: /usps/i, domains: ['usps.com'] },
    { name: 'HMRC', re: /\bHMRC\b/, token: /hmrc/i, domains: ['gov.uk'] },
    { name: 'IRS', re: /\bIRS\b/, token: /\birs\b/i, domains: ['irs.gov'] }
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
    'org.au', 'co.nz', 'co.in', 'co.jp', 'com.br', 'co.za', 'com.sg', 'com.mx'];

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
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[?[0-9a-f:]+:[0-9a-f:]*\]?$/i.test(host) && host.indexOf(':') !== -1;
  }

  function isOfficial(domain, brand) {
    return brand.domains.some(function (d) { return domain === d || domain.slice(-(d.length + 1)) === '.' + d; });
  }

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
    var all = value.match(/[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g);
    if (!all) return null;
    var addr = all[all.length - 1].toLowerCase();
    return { address: addr, domain: registrableDomain(addr.split('@')[1]) };
  }

  // ---------------------------------------------------------------------
  // Pre-processing: pull headers, links and attachment names out of the text
  // ---------------------------------------------------------------------

  function findHeader(text, name) {
    var re = new RegExp('^' + name + ':[ \\t]*(.*(?:\\r?\\n[ \\t]+.*)*)', 'im');
    var m = re.exec(text);
    if (!m) return null;
    return { value: m[1].replace(/\s+/g, ' ').trim(), index: m.index, length: m[0].length, raw: m[0] };
  }

  function findAllHeaders(text, name) {
    var re = new RegExp('^' + name + ':[ \\t]*(.*(?:\\r?\\n[ \\t]+.*)*)', 'gim');
    var out = [], m;
    while ((m = re.exec(text)) !== null) {
      out.push({ value: m[1].replace(/\s+/g, ' ').trim(), index: m.index, length: m[0].length });
    }
    return out;
  }

  function parseHeaders(text) {
    var h = {
      from: findHeader(text, 'From'),
      replyTo: findHeader(text, 'Reply-To'),
      returnPath: findHeader(text, 'Return-Path'),
      subject: findHeader(text, 'Subject'),
      authResults: findAllHeaders(text, 'Authentication-Results'),
      receivedSpf: findAllHeaders(text, 'Received-SPF')
    };
    h.present = !!(h.from || h.replyTo || h.returnPath || h.authResults.length || h.receivedSpf.length);
    h.hasAuth = h.authResults.length > 0 || h.receivedSpf.length > 0;
    return h;
  }

  function extractUrls(text) {
    var re = /\b(?:(?:https?|hxxps?):\/\/|www\.)[^\s<>"'`\]\[{}|\\^]+/gi;
    var out = [], seen = {}, m;
    while ((m = re.exec(text)) !== null) {
      var raw = m[0].replace(/[.,;:!?)]+$/, '');
      var host = '';
      try {
        var forParse = raw.replace(/^hxxp/i, 'http');
        if (/^www\./i.test(forParse)) forParse = 'http://' + forParse;
        var u = new URL(forParse);
        host = u.hostname.replace(/^\[|\]$/g, '');
      } catch (e) {
        continue;
      }
      var key = raw.toLowerCase();
      if (seen[key]) continue;
      seen[key] = true;
      out.push({
        raw: raw, index: m.index, length: raw.length,
        host: host.toLowerCase(), domain: registrableDomain(host),
        ip: isIP(host), https: /^https:/i.test(raw), hasAt: /^[a-z]+:\/\/[^\/]*@/i.test(raw)
      });
    }
    return out;
  }

  // Attachment-like file names. We blank out links and email addresses first
  // so that "example.com" or a web page ending in ".html" is not mistaken for
  // an attached file.
  function extractFiles(text) {
    var blanked = text
      .replace(/\b(?:(?:https?|hxxps?):\/\/|www\.)[^\s<>"']+/gi, function (s) { return ' '.repeat(s.length); })
      .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, function (s) { return ' '.repeat(s.length); });
    var all = EXEC_EXT.concat(MACRO_EXT, ODD_EXT);
    var re = new RegExp('(?:^|[\\s"\'(\\[:])([A-Za-z0-9][A-Za-z0-9_\\-]{0,60}?(?:\\.[A-Za-z0-9]{2,5})*\\.(' + all.join('|') + '))(?=$|[\\s"\'),.;:\\]])', 'gim');
    var out = [], seen = {}, m;
    while ((m = re.exec(blanked)) !== null) {
      var name = m[1].trim();
      var start = m.index + m[0].indexOf(m[1]) + (m[1].length - m[1].replace(/^\s+/, '').length);
      var key = name.toLowerCase();
      if (seen[key]) continue;
      seen[key] = true;
      var parts = name.toLowerCase().split('.');
      var ext = parts[parts.length - 1];
      var prev = parts.length > 2 ? parts[parts.length - 2] : '';
      out.push({
        name: name, index: start, length: name.length, ext: ext,
        doubleExt: DOC_EXT.indexOf(prev) !== -1
      });
    }
    return out;
  }

  // Link text that shows one address while the real link goes somewhere else.
  function findMisleadingLinks(text) {
    var out = [];
    var domainInText = /((?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,})/i;

    function check(shown, target, index, length) {
      var dm = domainInText.exec(shown);
      if (!dm) return;
      var shownHost;
      try {
        shownHost = new URL(/^https?:/i.test(dm[1]) ? dm[1] : 'http://' + dm[1]).hostname;
        var targetHost = new URL(target.replace(/^hxxp/i, 'http')).hostname;
        if (registrableDomain(shownHost) !== registrableDomain(targetHost)) {
          out.push({
            text: text.substr(index, length), index: index, length: length,
            note: 'Shows "' + shownHost + '" but actually goes to "' + targetHost + '"'
          });
        }
      } catch (e) { /* not a usable address */ }
    }

    var m;
    // HTML links: <a href="real">shown</a>
    var html = /<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
    while ((m = html.exec(text)) !== null) check(m[2].replace(/<[^>]+>/g, ''), m[1], m.index, m[0].length);
    // Markdown links: [shown](real)
    var md = /\[([^\]]+)\]\(((?:https?|hxxps?):\/\/[^)\s]+)\)/gi;
    while ((m = md.exec(text)) !== null) check(m[1], m[2], m.index, m[0].length);
    // Plain-text copies from mail apps: shown <real>
    var plain = /((?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}[^\s<]*)\s?<((?:https?|hxxps?):\/\/[^>\s]+)>/gi;
    while ((m = plain.exec(text)) !== null) check(m[1], m[2], m.index, m[0].length);
    return out.slice(0, MAX_EVIDENCE);
  }

  // ---------------------------------------------------------------------
  // THE RULES. Each one is a single, explainable warning sign.
  //   points   - exactly how much this sign adds to the score
  //   why      - plain-English reason it matters (shown to the user)
  //   detect   - returns a list of evidence; an empty list means "not found"
  // ---------------------------------------------------------------------
  var RULES = [
    {
      id: 'urgency', name: 'Urgency and pressure language', category: 'Social engineering', points: 10,
      why: 'Attackers rush you so you act before you think. Real organisations rarely demand action within minutes or hours.',
      detect: function (c) {
        return findPhrases(c.text, [
          /\burgent(ly)?\b/i, /\bimmediate(ly)?\b/i, /\bact now\b/i, /\bright away\b/i,
          /\bwithin (the next )?\d+ ?(hours?|hrs?|minutes?|mins?|days?)\b/i, /\b(final|last) (notice|warning|reminder|chance)\b/i,
          /\bexpires? (today|tonight|soon|in \d+)/i, /\btime[- ]sensitive\b/i, /\bas soon as possible\b/i,
          /\bdo not delay\b/i, /\bfailure to (respond|act|comply|verify|confirm|pay)\b/i, /\bbefore (it'?s too late|end of (the )?day)\b/i,
          /\btoday only\b/i, /\basap\b/i
        ]);
      }
    },
    {
      id: 'threat', name: 'Threat of account suspension or closure', category: 'Social engineering', points: 15,
      why: 'Threatening to lock, suspend or delete your account creates fear, which is a classic way to make people hand over details.',
      detect: function (c) {
        return findPhrases(c.text, [
          /\b(account|mailbox|access|service|subscription|profile)s? (has been|have been|will be|is being|may be) (suspended|locked|closed|disabled|deactivated|terminated|restricted|deleted|blocked|limited)\b/i,
          /\b(suspend|suspension of|close|closure of|deactivate|terminate|disable|restrict) (your|the) (account|mailbox|access|service)/i,
          /\bpermanently (deleted|disabled|closed|locked|removed)\b/i, /\b(will|may) (lose|be unable to) access\b/i,
          /\blegal action\b/i, /\bpenalt(y|ies)\b/i
        ]);
      }
    },
    {
      id: 'password', name: 'Request for your password', category: 'Credential theft', points: 25,
      why: 'Legitimate organisations never ask you to send or "confirm" your password by email or through a link in an email.',
      detect: function (c) {
        return findPhrases(c.text, [
          /\b(enter|confirm|verify|provide|update|re-?enter|send|submit|reply with|type|validate|re-?validate|keep)( us)? (your |the )?(current |existing |email |account |login )?(password|passcode|passphrase|login credentials|credentials|pin)\b/i,
          /\b(password|login credentials|credentials) (is|are) required\b/i,
          /\busername and password\b/i
        ], { negatable: true });
      }
    },
    {
      id: 'mfa', name: 'Request for an MFA or verification code', category: 'Credential theft', points: 25,
      why: 'One-time codes prove that YOU are logging in. Anyone who asks you to share one is probably trying to log in as you right now.',
      detect: function (c) {
        return findPhrases(c.text, [
          /\b(share|send|provide|reply with|enter|tell us|read (out|back)|forward|give us|confirm)( us)? (the |your |this )?(\d-digit |six-digit |one[- ]time )?(verification|security|authentication|authenticator|access|sms|2fa|mfa|otp|one[- ]time|login|confirmation) (code|pin|passcode)s?\b/i,
          /\b(send|forward|share|reply with) (us )?(the )?code (we|that was|you) (sent|received|get)/i
        ], { negatable: true });
      }
    },
    {
      id: 'giftcard', name: 'Gift card, cryptocurrency or untraceable payment request', category: 'Financial fraud', points: 25,
      why: 'Gift cards, crypto and wire transfers are almost impossible to reverse, which is exactly why scammers ask for them.',
      detect: function (c) {
        return findPhrases(c.text, [
          /\b(gift|itunes|apple|google play|steam|amazon|ebay|vanilla) ?cards?\b/i, /\bscratch (off )?the (back|code)/i,
          /\b(bitcoin|btc|ethereum|usdt|crypto(currency)?) (wallet|address|payment|transfer)\b/i,
          /\b(pay|send|transfer) .{0,20}\b(in|via|using) (bitcoin|crypto|btc)\b/i, /\bwestern union\b/i, /\bmoneygram\b/i
        ]);
      }
    },
    {
      id: 'payment', name: 'Payment or fee request', category: 'Financial fraud', points: 10,
      why: 'A message asking you to pay, even a small "fee", is a common trick. Small amounts lower your guard and capture your card details.',
      detect: function (c) {
        return findPhrases(c.text, [
          /\b(pay|settle|clear) (the |a |an |your )?(outstanding|overdue|small|redelivery|delivery|customs|shipping|processing|unpaid)? ?(balance|fee|amount|charge|invoice|payment|duty)\b/i,
          /\b(redelivery|delivery|customs|shipping|handling|processing|release) (fee|charge|payment|duty)\b/i,
          /\b(wire|bank) transfer\b/i, /\bprocess (the|a|this) (payment|transfer)\b/i, /\bpayment (is )?(required|needed|pending|failed)\b/i
        ]);
      }
    },
    {
      id: 'bankchange', name: 'Request to change bank or payment details', category: 'Financial fraud', points: 25,
      why: 'Changing where money is paid is the heart of Business Email Compromise (BEC) fraud. Always confirm by phone using a number you already know.',
      detect: function (c) {
        return findPhrases(c.text, [
          /\b(new|updated|changed|change (of|to|our|in)|update (to )?(our|your)|different) (bank(ing)?|payment|remittance|account|payroll|direct deposit) ?(details|information|info|account|instructions)?\b/i,
          /\b(bank(ing)?|payment|account) (details|information|instructions) (have|has) (changed|been updated)\b/i,
          /\b(iban|swift|bic|sort code|routing number|account number)\b/i,
          /\bdo not (use|pay (to|into)) (the|our) (old|previous)\b/i
        ]);
      }
    },
    {
      id: 'harvest', name: 'Credential-harvesting language', category: 'Credential theft', points: 20,
      why: 'Phrases like "verify your account" or "confirm your identity" usually lead to a fake login page built to steal what you type.',
      detect: function (c) {
        return findPhrases(c.text, [
          /\b(verify|confirm|validate|update|restore|unlock|reactivate|re-?activate|secure|review) (your )?(account|identity|login|mailbox|email|details|information|billing|payment (details|method|information))\b/i,
          /\b(log ?in|sign ?in|click (here|below|the (link|button)))( now)? to (verify|confirm|restore|keep|avoid|unlock|update|validate|review|secure|continue|reactivate|view)\b/i,
          /\bunusual (sign[- ]in|login|activity)\b/i, /\bsuspicious (sign[- ]in|login|activity)\b/i,
          /\bkeep (my |your )?(current )?password\b/i, /\bpassword (expires|will expire|has expired)\b/i
        ], { negatable: true });
      }
    },
    {
      id: 'impersonation', name: 'Possible brand impersonation', category: 'Impersonation', points: 15,
      why: 'The message mentions a well-known brand, but the sender address or the links use a domain that brand does not own.',
      detect: function (c) {
        var out = [];
        var domains = c.urls.map(function (u) { return u.domain; });
        var from = c.headers.from ? lastAddress(c.headers.from.value) : null;
        if (from) domains.push(from.domain);
        if (!domains.length) return out;
        BRANDS.forEach(function (b) {
          var m = b.re.exec(c.text);
          if (!m) return;
          var anyOfficial = domains.some(function (d) { return isOfficial(d, b); });
          if (anyOfficial) return;
          var where = from ? 'sender ' + from.address : 'links';
          out.push({ text: m[0], index: m.index, length: m[0].length,
            note: 'Mentions ' + b.name + ', but the ' + where + (from && c.urls.length ? ' and links' : '') + ' do not use an official ' + b.name + ' domain (' + b.domains[0] + ')' });
        });
        return out.slice(0, MAX_EVIDENCE);
      }
    },
    {
      id: 'greeting', name: 'Generic greeting', category: 'Impersonation', points: 5,
      why: 'Companies you have accounts with usually know your name. "Dear Customer" suggests a mass message sent to many people.',
      detect: function (c) {
        return findPhrases(c.text, [
          /\bdear (valued )?(customer|user|client|member|account holder|sir\/madam|sir or madam|beneficiary|recipient|employee|staff)\b/i,
          /\bhello (user|customer|dear)\b/i
        ]);
      }
    },
    {
      id: 'secrecy', name: 'Secrecy or authority pressure', category: 'Social engineering', points: 10,
      why: 'Asking you to keep something secret, or saying the boss cannot be reached, stops you from checking with anyone. This is common in CEO fraud.',
      detect: function (c) {
        return findPhrases(c.text, [
          /\bkeep (this|it) (confidential|private|between us|quiet|to yourself)\b/i, /\b(strictly|highly) confidential\b/i,
          /\b(do not|don'?t) (tell|discuss|mention|share this with) (anyone|others|colleagues)\b/i,
          /\b(i'?m|i am) (in a meeting|travel(l)?ing|on a flight|unavailable|not reachable)\b/i,
          /\b(can'?t|cannot|unable to) (take|answer) (calls|the phone|a call)\b/i, /\bare you (at your desk|available)\b/i
        ]);
      }
    },
    {
      id: 'invoice', name: 'Unexpected invoice or payment language', category: 'Financial fraud', points: 10,
      why: 'Fake invoices and "overdue" notices are a favourite attachment lure. This only matters if you were not expecting a bill from this sender.',
      detect: function (c) {
        return findPhrases(c.text, [
          /\binvoice\b/i, /\boverdue\b/i, /\boutstanding (balance|amount|payment|invoice)\b/i, /\bremittance\b/i,
          /\bpurchase order\b/i, /\bpayment (due|reminder|overdue)\b/i, /\bunpaid\b/i, /\bproforma\b/i
        ]);
      }
    },
    {
      id: 'ipurl', name: 'Link uses a raw IP address', category: 'Suspicious links', points: 20,
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
        return c.urls.filter(function (u) { return SHORTENERS.indexOf(u.domain) !== -1 || SHORTENERS.indexOf(u.host) !== -1; }).slice(0, MAX_EVIDENCE)
          .map(function (u) { return { text: u.raw, index: u.index, length: u.length, note: 'Uses the shortening service ' + u.host }; });
      }
    },
    {
      id: 'badurl', name: 'Suspicious-looking link', category: 'Suspicious links', points: 15,
      why: 'Fake sites often put a brand name or words like "login" and "secure" into an unrelated domain, so that a quick glance looks convincing.',
      detect: function (c) {
        var out = [];
        c.urls.forEach(function (u) {
          if (u.ip) return;
          var traits = [];
          var tld = u.host.split('.').pop();
          if (/xn--/.test(u.host)) traits.push('uses "xn--" encoding, which can disguise look-alike letters');
          if (u.hasAt) traits.push('contains "@", which hides the real destination after it');
          if (RISKY_TLDS.indexOf(tld) !== -1) traits.push('ends in ".' + tld + '", a domain ending often abused');
          if (/^(http|hxxp):/i.test(u.raw) && /log ?in|sign ?in|verify|account|secure|password|update|bank/i.test(u.raw)) traits.push('asks for sensitive actions without encryption (http, not https)');
          BRANDS.forEach(function (b) {
            if (b.token.test(u.host) && !isOfficial(u.domain, b)) traits.push('contains "' + b.name + '" but the real domain is ' + u.domain);
          });
          if (/(log-?in|sign-?in|verify|verification|secure|account|update|auth|wallet|support)/i.test(u.domain.split('.')[0]) && traits.length === 0)
            traits.push('the domain name itself (' + u.domain + ') uses security words to look official');
          if (u.host.split('.').length >= 5) traits.push('has an unusually long chain of sub-domains');
          if ((u.host.match(/-/g) || []).length >= 3) traits.push('has many hyphens in the domain');
          if (traits.length) out.push({ text: u.raw, index: u.index, length: u.length, note: traits.join('; ') });
        });
        return out.slice(0, MAX_EVIDENCE);
      }
    },
    {
      id: 'misleading', name: 'Misleading link text', category: 'Suspicious links', points: 20,
      why: 'The text you see shows one web address, but clicking would take you somewhere completely different.',
      detect: function (c) { return findMisleadingLinks(c.text); }
    },
    {
      id: 'execfile', name: 'Executable attachment type', category: 'Attachments', points: 30,
      why: 'These file types run programs on your computer when opened. They are one of the most common ways malware is delivered.',
      detect: function (c) {
        return c.files.filter(function (f) { return EXEC_EXT.indexOf(f.ext) !== -1; }).slice(0, MAX_EVIDENCE)
          .map(function (f) { return { text: f.name, index: f.index, length: f.length, note: '".' + f.ext + '" files can run code' }; });
      }
    },
    {
      id: 'macrofile', name: 'Macro-enabled Office file', category: 'Attachments', points: 15,
      why: 'Office files ending in "m" (like .docm or .xlsm) can contain macros: small programs that attackers use to install malware.',
      detect: function (c) {
        return c.files.filter(function (f) { return MACRO_EXT.indexOf(f.ext) !== -1; }).slice(0, MAX_EVIDENCE)
          .map(function (f) { return { text: f.name, index: f.index, length: f.length, note: '".' + f.ext + '" can contain macros' }; });
      }
    },
    {
      id: 'oddfile', name: 'Unusual attachment filename', category: 'Attachments', points: 15,
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
      id: 'macros', name: 'Asks you to enable macros or editing', category: 'Attachments', points: 25,
      why: 'Office blocks macros for safety. Asking you to "Enable Content" is how attackers switch that protection off.',
      detect: function (c) {
        return findPhrases(c.text, [
          /\benable (the )?(macros?|content|editing|active content)\b/i, /\bclick ["']?enable\b/i,
          /\ballow (the )?macros?\b/i, /\bturn on macros?\b/i
        ]);
      }
    },
    {
      id: 'replyto', name: 'Sender and Reply-To do not match', category: 'Email headers', points: 20,
      why: 'Replies would go to a different organisation than the one the email claims to be from. Attackers do this so your answer reaches them.',
      detect: function (c) {
        var f = c.headers.from && lastAddress(c.headers.from.value);
        var r = c.headers.replyTo && lastAddress(c.headers.replyTo.value);
        if (!f || !r || f.domain === r.domain) return [];
        return [{ text: c.headers.replyTo.raw.trim(), index: c.headers.replyTo.index, length: c.headers.replyTo.length,
          note: 'From uses ' + f.domain + ' but replies go to ' + r.domain }];
      }
    },
    {
      id: 'returnpath', name: 'Return-Path differs from sender', category: 'Email headers', points: 5,
      why: 'The technical bounce address belongs to a different domain. Newsletters do this legitimately, so it is only a weak signal on its own.',
      detect: function (c) {
        var f = c.headers.from && lastAddress(c.headers.from.value);
        var r = c.headers.returnPath && lastAddress(c.headers.returnPath.value);
        if (!f || !r || f.domain === r.domain) return [];
        return [{ text: c.headers.returnPath.raw.trim(), index: c.headers.returnPath.index, length: c.headers.returnPath.length,
          note: 'From uses ' + f.domain + ' but Return-Path uses ' + r.domain }];
      }
    },
    {
      id: 'spf', name: 'SPF check failed', category: 'Email authentication', points: 15,
      why: 'SPF lets a domain list which servers may send its mail. A failure means this email came from a server the domain did not approve.',
      detect: function (c) { return authFailures(c, /\bspf=(fail|softfail|permerror)\b/i, /^(fail|softfail|permerror)\b/i); }
    },
    {
      id: 'dkim', name: 'DKIM check failed', category: 'Email authentication', points: 15,
      why: 'DKIM is a digital signature on the email. A failure means the signature was missing, broken or the message was changed in transit.',
      detect: function (c) { return authFailures(c, /\bdkim=(fail|permerror|neutral)\b/i); }
    },
    {
      id: 'dmarc', name: 'DMARC check failed', category: 'Email authentication', points: 20,
      why: 'DMARC checks that the "From" domain you see is backed up by SPF or DKIM. A failure is a strong sign the sender address is forged.',
      detect: function (c) { return authFailures(c, /\bdmarc=(fail|permerror)\b/i); }
    }
  ];

  function authFailures(c, resultRe, spfHeaderRe) {
    var out = [];
    c.headers.authResults.forEach(function (h) {
      var m = resultRe.exec(h.value);
      if (m) out.push({ text: m[0], index: c.text.indexOf(m[0], h.index), length: m[0].length, note: 'Authentication-Results reports ' + m[0] });
    });
    if (spfHeaderRe) {
      c.headers.receivedSpf.forEach(function (h) {
        var m = spfHeaderRe.exec(h.value);
        if (m) out.push({ text: 'Received-SPF: ' + m[0], index: h.index, length: ('Received-SPF: ' + m[0]).length, note: 'Received-SPF reports ' + m[0] });
      });
    }
    return out.slice(0, 2);
  }

  // Which authentication checks passed (shown as reassurance, worth 0 points).
  function authPasses(h) {
    var joined = h.authResults.map(function (a) { return a.value; }).join(' ') + ' ' +
      h.receivedSpf.map(function (a) { return 'spf=' + a.value.split(' ')[0].toLowerCase(); }).join(' ');
    return ['spf', 'dkim', 'dmarc'].filter(function (k) { return new RegExp('\\b' + k + '=pass\\b', 'i').test(joined); });
  }

  // ---------------------------------------------------------------------
  // Recommendations, chosen based on which warning signs were found
  // ---------------------------------------------------------------------
  function recommendations(found, band) {
    var ids = {};
    found.forEach(function (f) { ids[f.id] = true; });
    var recs = [];
    if (band.level !== 'low') {
      recs.push('Do not click any links, open any attachments, or reply to this message.');
    }
    if (ids.password || ids.harvest || ids.mfa) {
      recs.push('If you already typed a password on a page from this email, change it straight away from the official website or app (type the address yourself), and change it anywhere else you reused it.');
    }
    if (ids.mfa) {
      recs.push('Never share a one-time or verification code with anyone. If you already did, contact the organisation\'s official support immediately and review your account sign-in activity.');
    }
    if (ids.bankchange || ids.payment || ids.giftcard || ids.invoice) {
      recs.push('Before paying anything or changing any payment details, call the person or company on a phone number you already have on file, not one from this email.');
    }
    if (ids.giftcard) {
      recs.push('No genuine business or manager pays bills with gift cards or cryptocurrency. Treat this as a scam.');
    }
    if (ids.execfile || ids.macrofile || ids.oddfile || ids.macros) {
      recs.push('Do not open the attachment, and never click "Enable Content" or "Enable Macros". If you opened it, disconnect from the network and contact your IT or security team.');
    }
    if (ids.impersonation || ids.replyto || ids.dmarc || ids.spf || ids.dkim) {
      recs.push('Check the real sender: go to the organisation\'s official website or app by typing the address yourself, and look for the same message there.');
    }
    if (band.level !== 'low') {
      recs.push('Report the message using your email app\'s "Report phishing" button, or forward it to your IT/security team, then delete it.');
    } else {
      recs.push('If the message asks you to do anything important, still confirm it through the organisation\'s official website, app or a contact you already know.');
      recs.push('Low risk is not the same as safe. If something feels off, trust your instinct and verify first.');
    }
    return recs;
  }

  // ---------------------------------------------------------------------
  // Main entry point
  // ---------------------------------------------------------------------
  function analyse(text) {
    text = String(text || '').replace(/\r\n?/g, '\n');
    var ctx = { text: text, headers: parseHeaders(text), urls: extractUrls(text), files: extractFiles(text) };

    var found = [];
    RULES.forEach(function (rule) {
      var evidence = rule.detect(ctx) || [];
      if (evidence.length) {
        found.push({ id: rule.id, name: rule.name, category: rule.category, points: rule.points, why: rule.why, evidence: evidence });
      }
    });

    var rawTotal = found.reduce(function (sum, f) { return sum + f.points; }, 0);
    var score = Math.min(100, rawTotal);
    var band = BANDS.filter(function (b) { return score >= b.min; })[0];

    return {
      score: score,
      rawTotal: rawTotal,
      band: band,
      indicators: found,
      recommendations: recommendations(found, band),
      stats: {
        links: ctx.urls.length,
        attachments: ctx.files.length,
        headersFound: ctx.headers.present,
        authFound: ctx.headers.hasAuth,
        authPasses: authPasses(ctx.headers),
        characters: text.length
      }
    };
  }

  var api = { analyse: analyse, RULES: RULES, BANDS: BANDS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else global.PhishAnalyser = api;
})(this);
