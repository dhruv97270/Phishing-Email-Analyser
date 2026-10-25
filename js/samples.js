/*
 * Demonstration emails. Every one of these is completely fictional.
 *
 * Safety: all addresses use domains reserved for documentation and testing
 * (".example", "example.com", "example.net", ".test", ".invalid") or the
 * documentation-only IP range 192.0.2.x, so none of them lead anywhere real.
 * The single short link uses a made-up path that is not a working link, and
 * the analyser only ever displays links as plain text, never as clickable links.
 */
(function (global) {
  'use strict';

  var SAMPLES = [
    {
      id: 'obvious',
      label: 'Obvious phishing',
      text: [
        'From: "PayPal Security Team" <security-alert@paypa1-support.example>',
        'Reply-To: recovery.desk@freemail.test',
        'Subject: URGENT!!! Your account has been SUSPENDED',
        'Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=paypa1-support.example; dkim=none; dmarc=fail header.from=paypa1-support.example',
        '',
        'Dear Customer,',
        '',
        'We detected unusual activity on your PayPal account. Your account has been suspended',
        'and will be permanently deleted within 24 hours unless you verify your account immediately.',
        '',
        'To restore access, click here to verify: http://192.0.2.45/paypal/login.php',
        'or use this quick link: https://bit.ly/DEMO-not-a-real-link',
        '',
        'You must enter your password and card number on the secure page.',
        'Failure to respond will result in legal action.',
        '',
        'Attached: Account_Recovery_Form.pdf.exe',
        '',
        'PayPal Security Department'
      ].join('\n')
    },
    {
      id: 'sophisticated',
      label: 'Sophisticated phishing',
      text: [
        'From: "Daniel Okafor" <d.okafor@northwind-traders.example>',
        'Reply-To: "Daniel Okafor" <d.okafor@northwind-traders.example>',
        'Subject: Re: Q3 compensation review - your input needed',
        'Authentication-Results: mx.northwind-traders.example; spf=pass smtp.mailfrom=mailer-relay.example; dkim=fail header.d=northwind-traders.example; dmarc=fail header.from=northwind-traders.example',
        '',
        'Hi Priya,',
        '',
        'Following on from Tuesday\'s leadership meeting, HR has shared the draft Q3 compensation',
        'review in SharePoint. Could you take a look at your team\'s section before Friday?',
        '',
        'The document is here:',
        'https://northwind.sharepoint.com/sites/HR/Q3-Review <https://northwind-sharepoint.docs-viewer.example/auth/session?id=8812>',
        '',
        'You may be asked to sign in again because the file is restricted to managers.',
        'Please keep this confidential until the announcement next month.',
        '',
        'Thanks,',
        'Daniel',
        '',
        'Daniel Okafor | Head of People Operations',
        'Northwind Traders (fictional company)'
      ].join('\n')
    },
    {
      id: 'm365',
      label: 'Fake Microsoft 365 warning',
      text: [
        'From: "Microsoft 365 Admin Center" <no-reply@m365-notifications.example>',
        'Reply-To: support@m365-notifications.example',
        'Subject: Action required: Your Microsoft 365 password expires today',
        'Received-SPF: SoftFail (domain of transitioning m365-notifications.example does not designate 198.51.100.23 as permitted sender)',
        '',
        'Microsoft 365',
        '',
        'Hello user,',
        '',
        'Your password expires today. To avoid losing access to Outlook, Teams and OneDrive,',
        'you must keep your current password by confirming it below.',
        '',
        'Keep My Current Password: https://login-microsoftonline.account-verify.example/common/oauth2/keep',
        '',
        'After signing in, enter the 6-digit verification code sent to your phone to finish.',
        'If you do not act within 12 hours, your mailbox will be disabled.',
        '',
        'Thank you,',
        'The Microsoft 365 Team'
      ].join('\n')
    },
    {
      id: 'parcel',
      label: 'Fake parcel delivery',
      text: [
        'From: "DHL Express" <delivery@dhl-parcel-tracking.example>',
        'Subject: Your parcel is on hold - redelivery fee required',
        '',
        'Dear customer,',
        '',
        'We attempted to deliver your package today but it could not be delivered because of',
        'an unpaid customs fee of £1.99.',
        '',
        'Your parcel will be returned to the sender if the fee is not paid within 48 hours.',
        '',
        'Pay the redelivery fee and choose a new delivery date here:',
        'http://dhl-redelivery-secure.example/track?parcel=GB00000000DEMO',
        '',
        'Tracking number: GB00000000DEMO',
        '',
        'DHL Customer Service'
      ].join('\n')
    },
    {
      id: 'bec',
      label: 'Fake invoice / BEC',
      text: [
        'From: "Brightline Supplies - Accounts" <accounts@brightline-supplies.example>',
        'Reply-To: brightline.accounts.dept@freemail.test',
        'Return-Path: <bounce@bulk-sender.invalid>',
        'Subject: Overdue invoice INV-20431 and updated bank details',
        'Authentication-Results: mx.example.com; spf=softfail smtp.mailfrom=bulk-sender.invalid; dkim=none; dmarc=fail header.from=brightline-supplies.example',
        '',
        'Good morning,',
        '',
        'Our records show invoice INV-20431 for £18,450.00 is now overdue. Please note that',
        'our bank details have changed following an audit, so do not pay into the old account.',
        '',
        'New account name: Brightline Supplies Ltd',
        'Sort code: 00-00-00   Account number: 00000000 (demo values)',
        '',
        'Please process the payment today and confirm by reply. The updated invoice is attached as',
        'INV-20431_updated.docm. When you open it, click Enable Content to view the remittance form.',
        '',
        'I am travelling this week and cannot take calls, so email is best. Please keep this',
        'confidential until the audit is complete.',
        '',
        'Kind regards,',
        'Martin Hale',
        'Accounts Receivable, Brightline Supplies (fictional company)'
      ].join('\n')
    },
    {
      id: 'legit',
      label: 'Legitimate email',
      text: [
        'From: "Riverside Library" <events@riverside-library.example>',
        'Reply-To: events@riverside-library.example',
        'Subject: Book club this Thursday at 6pm',
        'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=riverside-library.example; dkim=pass header.d=riverside-library.example; dmarc=pass header.from=riverside-library.example',
        '',
        'Hi Sam,',
        '',
        'Just a friendly reminder that our monthly book club meets this Thursday at 6pm in the',
        'community room. This month we are discussing "The Lighthouse Keeper".',
        '',
        'Light refreshments will be provided. If you can no longer make it, no need to reply,',
        'just come along next month instead.',
        '',
        'The full events calendar is on our website: https://www.riverside-library.example/events',
        '',
        'We will never ask you for your password or any verification code by email.',
        '',
        'See you there,',
        'Alex',
        'Riverside Library (fictional organisation)'
      ].join('\n')
    }
  ];

  if (typeof module !== 'undefined' && module.exports) module.exports = SAMPLES;
  else global.PHISH_SAMPLES = SAMPLES;
})(this);
