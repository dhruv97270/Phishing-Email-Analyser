# How the Phishing Email Analyser works

This guide explains the analysis step by step, in plain English, so you can understand (and
defend in an interview) every part of the score.

## 1. The pipeline

```
Pasted email text
      │
      ├─► Header parser   → From, Reply-To, Return-Path, Authentication-Results, Received-SPF
      ├─► Link extractor  → every URL, its host, registrable domain, IP or not, https or not
      ├─► File extractor  → attachment-like file names (links and email addresses blanked first)
      │
      ▼
 25 independent rules  → each returns a list of evidence (empty = not found)
      │
      ▼
 Score = sum of points of rules that fired, capped at 100
      │
      ▼
 Band (Low / Suspicious / High) + tailored recommendations + highlighted email
```

All of this happens in `js/analyser.js`, inside the browser. No step touches the network.

## 2. Why fixed points?

A fixed points table is **explainable and auditable**: anyone can see why an email scored 65,
challenge a weight, and change it. Each rule fires **once**, so an email that says "urgent" ten
times does not outscore one with a real credential request. Heavier weights go to signs that are
rarely innocent (executable attachments, MFA code requests, bank-detail changes); lighter weights
go to signs that legitimate mail also shows (invoice language, Return-Path differences).

## 3. Rules and the attacker technique behind them

| Rule | Points | What it looks for | MITRE ATT&CK |
|---|---|---|---|
| Urgency and pressure | 10 | "urgent", "within 24 hours", "final notice", "failure to respond" | Social engineering in T1566 |
| Threat of suspension | 15 | "account has been suspended", "permanently deleted", "legal action" | T1566 |
| Secrecy / authority | 10 | "keep this confidential", "I'm travelling", "can't take calls" | T1656 Impersonation (CEO/BEC fraud) |
| Password request | 25 | "enter / confirm / verify your password" (ignores "never" sentences) | T1598 Phishing for Information |
| MFA code request | 25 | "enter the 6-digit verification code", "send us the code" | T1111 MFA Interception |
| Credential harvesting | 20 | "verify your account", "unusual sign-in activity", "keep your current password" | T1598.003 Spearphishing Link |
| Gift card / crypto / wire | 25 | gift cards, Bitcoin wallets, Western Union | T1656 Impersonation (financial fraud) |
| Bank details change | 25 | "our bank details have changed", sort code, IBAN, "do not pay into the old account" | T1656 (Business Email Compromise) |
| Payment or fee | 10 | "redelivery fee", "customs fee", "process the payment" | T1566.002 |
| Invoice language | 10 | invoice, overdue, remittance, purchase order | T1566.001 lure |
| Brand impersonation | 15 | a brand (Microsoft, PayPal, DHL…) is named but no link or sender uses its real domain | T1656, T1583.001 look-alike domains |
| Generic greeting | 5 | "Dear Customer", "Hello user" | Mass phishing indicator |
| Raw IP link | 20 | `http://192.0.2.45/login` | T1566.002 Spearphishing Link |
| Shortened link | 15 | bit.ly, tinyurl and similar | T1566.002 |
| Suspicious link | 15 | brand name in an unrelated domain, punycode (`xn--`), `@` in a URL, abused endings, http for login pages | T1566.002, T1583.001 |
| Misleading link text | 20 | shown address differs from real target (HTML, Markdown or `text <url>` form) | T1566.002 |
| Executable attachment | 30 | .exe .js .scr .vbs .lnk .hta .msi … | T1566.001, T1204.002 Malicious File |
| Enable macros | 25 | "click Enable Content", "enable macros" | T1204.002 |
| Macro-enabled Office file | 15 | .docm .xlsm .pptm … | T1566.001 |
| Unusual attachment | 15 | double extension (`invoice.pdf.exe`), .iso, .img, .html, .zip, .one | T1566.001, T1553.005 (ISO MOTW bypass) |
| Reply-To mismatch | 20 | From and Reply-To use different domains | T1566 / BEC |
| Return-Path mismatch | 5 | bounce domain differs (weak: newsletters do this) | Spoofing indicator |
| SPF fail | 15 | `spf=fail/softfail/permerror` or `Received-SPF: Fail/SoftFail` | Sender spoofing |
| DKIM fail | 15 | `dkim=fail/permerror/neutral` | Message tampering or forgery |
| DMARC fail | 20 | `dmarc=fail` | From-domain spoofing |

## 4. Email authentication in one minute

- **SPF** asks: *was this sent by a server the domain says is allowed to send its mail?*
- **DKIM** asks: *does the message carry a valid digital signature from the domain, unchanged in transit?*
- **DMARC** asks: *does the visible From domain line up with a passing SPF or DKIM check?* A DMARC
  failure is one of the strongest technical signs that the sender address is forged.

The analyser reads these results from the `Authentication-Results` and `Received-SPF` headers
that the receiving mail server already added. It does not perform DNS lookups itself (that would
require network access).

## 5. Avoiding false positives

- **Negation:** password and code rules skip matches in sentences containing "never", "do not",
  "won't" etc.
- **Attachment names:** URLs and email addresses are blanked out before searching for file names,
  so `example.com` or `page.html` in a link is not treated as an attachment.
- **Official domains:** brand rules compare against each brand's real domains
  (e.g. `microsoft.com`, `office.com`, `sharepoint.com`), using the registrable domain so
  `login.microsoftonline.com` counts as Microsoft but `login-microsoftonline.account-verify.example` does not.

## 6. Tuning

Open `js/analyser.js`, find the rule, and change its `points`. The score bands live in the
`BANDS` list at the top of the same file. The page's "How the score works" table updates itself.
