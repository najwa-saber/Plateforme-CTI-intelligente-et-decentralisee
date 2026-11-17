# Synthetic CTI corpus - category: phishing
# Markup: <<type|display>> or <<type|display|gold_value>> ; hashes: <<md5|@seed>> / <<sha256|@seed>>
# All indicators are fictitious (RFC 5737 IPs, RFC 2606/6761 domains). Actors and products are invented.

REPORTS = [
    dict(id="CTI-001", campaign="PH-C1", mitre=["T1566.002", "T1598.003"], ambiguous=False, published="2026-02-03",
         title="Payroll credential harvesting campaign",
         text="""Between 2 and 3 February, employees of several logistics firms received emails claiming that their
salary slip was available. The message urged recipients to confirm their identity before the payment date.
The link pointed to <<url|hxxps://payroll-portal-secure[.]example/verify|https://payroll-portal-secure.example/verify>>,
a cloned single sign-on page hosted on <<ipv4|198.51.100.24>>. Submitted usernames and passwords were posted
to a PHP collector. The sender domain <<domain|payroll-portal-secure.example>> was registered two days before the
campaign. No attachment was used; the operation relied entirely on credential theft through a spoofed portal."""),
    dict(id="CTI-002", campaign="PH-C3", mitre=["T1566.002", "T1557"], ambiguous=False, published="2026-03-11",
         title="Adversary-in-the-middle phishing against Microsoft 365 tenants",
         text="""A reverse-proxy phishing kit is being used to bypass multi-factor authentication. Victims receive a
shared-document notification and are redirected to <<url|https://login-m365-verify.example/common/oauth2>>.
The proxy relays the real sign-in flow and steals the session cookie once MFA is completed, allowing the
attacker to replay the token. Infrastructure resolved to <<ipv4|203.0.113.45>>. Within hours, inbox rules were
created to hide security alerts. Organisations should monitor impossible-travel sign-ins and token reuse
originating from <<domain|login-m365-verify.example>>."""),
    dict(id="CTI-003", campaign="PH-C2", mitre=["T1566.002"], ambiguous=False, published="2026-01-19",
         title="Parcel delivery SMS phishing wave",
         text="""A smishing wave impersonating a national postal service asked recipients to pay a small customs fee.
Text messages contained the short link <<url|http://track-parcel-delivery.test/p/8812>>. The landing page
collected card numbers, expiry dates and one-time passwords. The domain <<domain|track-parcel-delivery.test>>
rotated hosting between <<ipv4|192.0.2.61>> and <<ipv4|192.0.2.62>>. Messages were sent from foreign mobile numbers
and the kit geo-fenced visitors so that crawlers outside the target country only saw a blank page."""),
    dict(id="CTI-004", campaign="PH-C4", mitre=["T1566.001", "T1204.002"], ambiguous=False, published="2026-04-02",
         title="Invoice lure with malicious HTML attachment",
         text="""Finance departments were targeted with emails titled 'Overdue invoice - action required'. The
attachment Invoice_8841.html opened a fake webmail login form rendered locally, which avoided URL reputation
filters. Captured credentials were sent through a POST request to
<<url|hxxp://invoice-docs-share[.]test/collect.php|http://invoice-docs-share.test/collect.php>>. The attachment had
the MD5 <<md5|@ph-c4-html>>. Sender addresses spoofed a known supplier and the reply-to header pointed to a free mail
service. Users who entered their password were later targeted by business email compromise attempts."""),
    dict(id="CTI-005", campaign="PH-C1", mitre=["T1566.002"], ambiguous=False, published="2026-02-09",
         title="Second wave of the payroll portal phishing",
         text="""The payroll-themed operation observed earlier this month resumed with new wording about a bonus
payment. The kit is unchanged and still posts stolen credentials to <<ipv4|198.51.100.24>>. A new lookalike
domain, <<domain|payroll-bonus-secure.example>>, was added alongside the original <<domain|payroll-portal-secure.example>>.
Emails were sent through a compromised newsletter account, which explains the valid SPF results. Recipients
were mainly HR and accounting staff of mid-sized companies."""),
    dict(id="CTI-006", campaign="PH-C5", mitre=["T1566.004", "T1598.004"], ambiguous=False, published="2026-05-14",
         title="Voice phishing targeting help desk staff",
         text="""Callers impersonating employees contacted the IT help desk and requested a password reset and the
enrolment of a new MFA device. They used personal details gathered from social networks to answer
verification questions. After the reset, the attacker logged in from <<ipv4|203.0.113.150>> and searched the mailbox
for payment information. The same group later sent follow-up emails from <<domain|it-helpdesk-support.test>> asking
other staff to approve push notifications. Help desks should enforce call-back verification."""),
    dict(id="CTI-007", campaign="PH-C3", mitre=["T1566.002", "T1557"], ambiguous=False, published="2026-03-20",
         title="Session token theft linked to M365 phishing kit",
         text="""Incident responders investigating unauthorised mailbox access traced the initial event to a
document-sharing email. The victim authenticated on a proxied page served by <<domain|login-m365-verify.example>>,
which captured the session cookie. A second hostname, <<domain|sso-m365-verify.example>>, was registered by the same
actor. Both resolved to <<ipv4|203.0.113.45>>. The intruder downloaded contact lists and sent internal phishing to
colleagues. Revoking refresh tokens and resetting credentials stopped the activity."""),
    dict(id="CTI-008", campaign="PH-C6", mitre=["T1566.002", "T1204.001"], ambiguous=False, published="2026-06-01",
         title="QR code phishing in fake parking fines",
         text="""Printed notices placed on car windshields asked drivers to scan a QR code to pay a parking fine.
The code opened <<url|https://city-parking-pay.example/fine?ref=55A1>> on the mobile phone, outside corporate
protections. The page requested card data and a mobile banking password. Email variants of the same lure
embedded the QR code in a PDF attachment so that secure email gateways could not inspect the link. The domain
was hosted on <<ipv4|192.0.2.201>> and used a free TLS certificate."""),
    dict(id="CTI-009", campaign="PH-C2", mitre=["T1566.002"], ambiguous=False, published="2026-01-27",
         title="Postal smishing kit reused with new domains",
         text="""The customs fee smishing kit reappeared with fresh domains. Messages now link to
<<url|http://parcel-redelivery.test/r/119>> while the older <<domain|track-parcel-delivery.test>> redirects to the same
panel. Collected card data is exfiltrated to a messaging bot. The hosting IP <<ipv4|192.0.2.62>> is shared with the
previous wave. The kit checks the user agent and only displays the form to mobile browsers."""),
    dict(id="CTI-010", campaign="PH-C7", mitre=["T1566.001", "T1204.002"], ambiguous=True, published="2026-06-22",
         title="CV-themed phishing delivering a password stealer",
         text="""Recruiters received emails from fake candidates with a ZIP archive named Resume_Julia.zip. The archive
contained a shortcut file that downloaded a small password stealer from
<<url|hxxp://cv-portfolio-host[.]example/files/resume.bin|http://cv-portfolio-host.example/files/resume.bin>>. The
dominant activity is the phishing delivery; the payload (SHA-256 <<sha256|@ph-c7-stealer>>) only collected browser
passwords. The social-engineering pretext was carefully crafted around open job offers published on LinkedIn."""),
    dict(id="CTI-011", campaign="PH-C8", mitre=["T1566.002", "T1598.003"], ambiguous=False, published="2026-07-08",
         title="Fake shared-drive notification phishing",
         text="""Users were notified that a colleague had shared a confidential spreadsheet. The button led to a
lookalike file-sharing portal at <<domain|drive-share-files.test>>, which asked for corporate credentials before
displaying the document. Credential submissions were forwarded to <<ipv4|198.51.100.190>>. The emails came from
compromised accounts of partner companies, so the sender reputation was good and the messages bypassed filtering.
Security awareness teams should remind staff to open shared documents from the official application only."""),
    dict(id="CTI-012", campaign="PH-C1", mitre=["T1566.002"], ambiguous=False, published="2026-02-15",
         title="Payroll portal phishing - infrastructure update",
         text="""Tracking of the payroll credential harvesting operation shows a migration of the collector to a new
server while <<ipv4|198.51.100.24>> remains in use as a redirector. The phishing page is now reachable at
<<url|https://payroll-portal-secure.example/login>>. Analysts noticed the kit added a CAPTCHA to evade automated
scanners. Indicators from the previous reports remain relevant and should stay on block lists."""),
    dict(id="CTI-013", campaign="PH-C9", mitre=["T1566.003"], ambiguous=False, published="2026-08-03",
         title="Phishing through collaboration chat messages",
         text="""External tenants sent chat messages to employees claiming to be the internal IT team. The messages
explained that the mailbox was full and requested the user to re-authenticate via
<<url|https://teams-it-support.example/mailbox>>. Because external chat was allowed by default, the messages were
delivered without warning banners. The landing page harvested credentials and forwarded them to
<<ipv4|203.0.113.201>>. Restricting external chat federation reduced the exposure."""),
    dict(id="CTI-014", campaign="PH-C3", mitre=["T1566.002", "T1557"], ambiguous=False, published="2026-04-05",
         title="AiTM phishing infrastructure expansion",
         text="""The reverse-proxy phishing operation targeting cloud email expanded with three new hostnames:
<<domain|auth-m365-verify.example>>, <<domain|login-m365-verify.example>> and <<domain|mfa-m365-verify.example>>.
All of them point to <<ipv4|203.0.113.45>> or to the neighbouring <<ipv4|203.0.113.46>>. The phishing emails now
impersonate voicemail notifications. Detection should rely on conditional access policies and token
binding rather than on domain block lists alone, because new domains are registered every week."""),
    dict(id="CTI-015", campaign="PH-C10", mitre=["T1566.001"], ambiguous=False, published="2026-09-12",
         title="Tax refund phishing with PDF lure",
         text="""During the tax season, citizens received emails announcing a refund. The PDF attachment, MD5
<<md5|@ph-c10-pdf>>, contained a button to <<url|http://tax-refund-claim.test/form>> where victims entered their
bank account and identity information. The sender display name copied the tax administration. The campaign
targeted personal addresses rather than corporate inboxes and was relayed by a botnet of compromised servers."""),
    dict(id="CTI-016", campaign="PH-C11", mitre=["T1566.002", "T1598.003"], ambiguous=False, published="2026-10-01",
         title="Crypto wallet phishing via fake support portal",
         text="""Users of a cryptocurrency wallet were contacted on social media by fake support agents. They were asked
to 'synchronise' their wallet on <<domain|wallet-sync-support.example>>, which requested the recovery phrase.
Several victims lost funds within minutes. The phishing site was served from <<ipv4|192.0.2.88>> and protected by
a reverse proxy. The legitimate project never asks users to share their seed phrase."""),
    dict(id="CTI-017", campaign="PH-C12", mitre=["T1566.002"], ambiguous=False, published="2026-10-14",
         title="Bank impersonation phishing targeting SMEs",
         text="""Small businesses received emails pretending to come from their bank and warning about a blocked
transfer. The link led to <<url|hxxps://secure-bank-validation[.]test/unlock|https://secure-bank-validation.test/unlock>>,
which reproduced the online banking interface and asked for the activation code sent by SMS. Operators then
called the victims to obtain additional codes. Hosting was traced to <<ipv4|198.51.100.211>>."""),
    dict(id="CTI-018", campaign="PH-C3", mitre=["T1566.002", "T1557"], ambiguous=False, published="2026-05-02",
         title="Business email compromise following AiTM phishing",
         text="""A manufacturing company suffered a payment fraud after an accountant authenticated on a proxied login
page at <<domain|login-m365-verify.example>>. The attacker reused the stolen session from <<ipv4|203.0.113.46>> and
inserted himself in an ongoing conversation with a supplier, changing the bank details of an invoice. The
transfer was recovered thanks to a quick reaction by the bank. Phishing awareness and payment verification
procedures were reinforced."""),
    dict(id="CTI-019", campaign="PH-C13", mitre=["T1566.001", "T1204.002"], ambiguous=True, published="2026-11-02",
         title="Calendar invitation phishing with malicious ICS",
         text="""Attackers abused calendar invitations: the ICS file included a meeting link to
<<url|https://meeting-join-now.example/j/4471>> that requested credentials before joining. The invitation was
automatically added to calendars even when the email was quarantined. Some variants also offered a 'meeting
plugin' with SHA-256 <<sha256|@ph-c13-plugin>>, but the main objective of the campaign remained credential
phishing. The domain was hosted behind <<ipv4|192.0.2.120>>."""),
    dict(id="CTI-020", campaign="PH-C14", mitre=["T1598.003"], ambiguous=False, published="2026-11-09",
         title="Spearphishing for information against researchers",
         text="""Academic researchers working on energy policy were approached by a fictitious journalist asking for
an interview. After building trust over several emails, the actor sent a link to a questionnaire hosted at
<<url|https://press-interview-forms.test/q/7>>, which required logging in with a university account. The goal was
to collect credentials and information about ongoing projects. The domain <<domain|press-interview-forms.test>>
was linked to <<ipv4|203.0.113.18>>, previously used in similar social-engineering operations."""),
]
