# How the Phishing Email Analyser works

This guide explains the analysis step by step, in plain English, so you can understand (and
defend in an interview) every part of the score.

## 1. The pipeline

```
Pasted email text or .eml file
      │
      ▼
 DECODE   headers split from body · encoded subjects (=?UTF-8?Q?...?=) decoded
          MIME parts walked · quoted-printable / base64 decoded · HTML turned into visible text
          every link's shown text AND real target remembered · real attachment names collected
      │
      ▼
 EXTRACT  sender domain · Reply-To · Return-Path · SPF / DKIM / DMARC results and their alignment
          links (own domain? click-tracking service? IP? shortener?) · attachment-like file names
      │
      ▼
 RULES    27 warning-sign rules (+ points) and 3 reassuring-sign rules (− points)
      │
      ▼
 CONTEXT  no dangerous sign → score stops at 59 · verified sender + no dangerous sign → stops at 29
          dangerous sign present → reassuring signs do not count
      │
      ▼
 RESULT   0–100 score · Low / Suspicious / High · evidence · recommendations · highlighted email
```

All of this happens in `js/analyser.js`, inside the browser. No step touches the network.

## 2. Why decode first?

A raw email ("Show original") is not what you see on screen. Marketing emails are usually
quoted-printable or base64-encoded HTML, full of CSS, hidden tracking pixels and long tracking
links. Reading that raw text produces false alarms (code fragments, tracking hosts, broken words
like `de=\nlivery`). Decoding first means the rules only look at the message a person actually
reads, and the link checks see both the text of each link and where it really goes.

## 3. Why fixed points and context limits?

A fixed points table is **explainable and auditable**: anyone can see why an email scored 60,
challenge a weight, and change it. Each rule fires **once**, so an email that says "urgent" ten
times does not outscore one with a real credential request.

Points alone caused a real false positive in version 1: a genuine DoorDash marketing email with
passing SPF, DKIM and DMARC was rated High Risk because sales wording, receipts and click-tracking
links added up. Version 2 adds three explainable context limits:

- **Dangerous signs.** Rules marked ⚠ (credential or payment requests, risky attachments,
  misleading links, forged or look-alike senders) are what real phishing needs to succeed.
  Without at least one, the score stops at 59.
- **Verified sender.** If DMARC passes *and aligns with the From domain* (and that domain is not a
  free-mail or look-alike domain), reassuring signs subtract points and, with no dangerous sign,
  the score stops at 29.
- **Danger beats verification.** If a dangerous sign is present, reassuring signs do not count.
  Authentication proves which domain sent the email, not that the request is safe: accounts get
  hacked, and scammers can authenticate domains they own.

## 4. Rules and the attacker technique behind them

| Rule | Points | What it looks for | MITRE ATT&CK |
|---|---|---|---|
| Urgency and pressure | +10 | "urgent", "within 24 hours", "final notice", "failure to respond" | Social engineering in T1566 |
| Sales-style urgency | +3 | "offer ends today", "limited time", "act now" (normal in marketing, so low) | — |
| Threat of suspension | +15 | "account has been suspended", "permanently deleted", "legal action" | T1566 |
| Secrecy / authority | +10 | "keep this confidential", "I'm travelling", "can't take calls" | T1656 Impersonation (CEO/BEC fraud) |
| ⚠ Password request | +25 | "enter / confirm / verify your password" (ignores "never" sentences) | T1598 Phishing for Information |
| ⚠ MFA code request | +25 | "enter the 6-digit verification code", "send us the code" | T1111 MFA Interception |
| ⚠ Credential harvesting | +20 | "verify your account", "unusual sign-in activity", "keep your current password" | T1598.003 Spearphishing Link |
| ⚠ Gift card / crypto / wire | +25 | buying gift cards, Bitcoin wallets, Western Union | T1656 Impersonation (financial fraud) |
| ⚠ Bank details change | +25 | "our bank details have changed", sort code, IBAN, "do not pay into the old account" | T1656 (Business Email Compromise) |
| ⚠ Fee or balance request | +10 | "pay the redelivery fee", "customs fee", "process the payment" | T1566.002 |
| Invoice language | +5 | invoice, overdue, remittance, purchase order | T1566.001 lure |
| ⚠ Look-alike domain | +30 | letter swaps or one-letter typos of a brand (`paypa1`, `rnicrosoft`, `d00rdash`) | T1583.001 Acquire Domains |
| ⚠ Brand impersonation | +15 | sender name or subject claims a brand, but the From domain is not the brand's | T1656 |
| Generic greeting | +5 | "Dear Customer", "Hello user" | Mass phishing indicator |
| ⚠ Raw IP link | +20 | `http://192.0.2.45/login` | T1566.002 Spearphishing Link |
| Shortened link | +15 | bit.ly, tinyurl and similar | T1566.002 |
| Suspicious link | +15 | brand name in an unrelated domain, punycode (`xn--`), `@` in a URL, abused endings, http for login pages (skips the sender's own verified domain and click-tracking services) | T1566.002, T1583.001 |
| ⚠ Misleading link text | +20 | shown address differs from real target (HTML, Markdown or `text <url>` form); a verified sender's own address routed through a click tracker is allowed | T1566.002 |
| ⚠ Executable attachment | +30 | .exe .js .scr .vbs .lnk .hta .msi … | T1566.001, T1204.002 Malicious File |
| ⚠ Enable macros | +25 | "click Enable Content", "enable macros" | T1204.002 |
| ⚠ Macro-enabled Office file | +15 | .docm .xlsm .pptm … | T1566.001 |
| ⚠ Unusual attachment | +15 | double extension (`invoice.pdf.exe`), .iso, .img, .html, .zip, .one | T1566.001, T1553.005 (MOTW bypass) |
| ⚠ Reply-To mismatch | +20 | From and Reply-To use different domains | T1566 / BEC |
| Return-Path mismatch | +5 | bounce domain differs (skipped for verified senders and mailing services) | Spoofing indicator |
| ⚠ SPF fail | +15 | SPF fail / softfail / permerror (only if no SPF pass) | Sender spoofing |
| ⚠ DKIM fail | +15 | DKIM fail / permerror (only if no DKIM pass) | Message tampering or forgery |
| ⚠ DMARC fail | +20 | `dmarc=fail` | From-domain spoofing |
| DMARC pass, aligned | −15 | DMARC passed for the same domain shown in From | Reassuring |
| DKIM pass, aligned | −10 | a valid signature from the From domain | Reassuring |
| SPF pass, aligned | −5 | the sending server is approved for the From domain | Reassuring |

## 5. Email authentication in one minute

- **SPF** asks: *was this sent by a server the domain says is allowed to send its mail?*
- **DKIM** asks: *does the message carry a valid digital signature from the domain, unchanged in transit?*
- **DMARC** asks: *does the visible From domain line up with a passing SPF or DKIM check?* A DMARC
  failure is one of the strongest technical signs that the sender address is forged.
- **Alignment** matters: an SPF pass for `bulk-mailer.example` says nothing about an email whose
  From is `yourbank.example`. The analyser only gives reassuring points when the passing domain
  matches the From domain.

The analyser reads these results from the `Authentication-Results` and `Received-SPF` headers
that the receiving mail server already added. It does not perform DNS lookups itself (that would
require network access).

## 6. Avoiding false positives

- **Decoding and HTML stripping** so CSS, tracking pixels and encoded fragments are never read as words.
- **Headers are not scanned for wording.** Only the subject and body are, so `Delivered-To: you@gmail.com` is not mistaken for a Google impersonation.
- **Negation:** password and code rules skip matches in sentences containing "never", "do not", "won't" etc.
- **Attachment names:** URLs and email addresses are blanked out before searching for file names.
- **Brand checks** look at who the email *claims* to be (sender name and subject), not every brand mentioned in passing ("Download on the App Store").
- **Click-tracking services** (SendGrid, Mailchimp, Amazon SES, HubSpot, Braze, Klaviyo, Proofpoint URL Defense, Outlook Safe Links and others) are recognised as normal.

## 7. Tuning

Open `js/analyser.js`, find the rule, and change its `points` or its `danger` flag. The score
bands and context limits live at the top of the same file. The page's "How the score works" table
updates itself.
