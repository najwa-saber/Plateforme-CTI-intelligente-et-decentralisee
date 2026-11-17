"""Keyword / expression rules mapping report content to ATT&CK techniques (CDC 6.2).

Each rule lists characteristic expressions. A match is a *proposal* supported by
textual evidence, never a proof that the technique was used.
Technique identifiers are checked against the official catalogue at load time
(rules referring to revoked/deprecated techniques are ignored and reported).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MitreRule:
    technique_id: str
    patterns: tuple[str, ...]
    base_confidence: float
    rationale: str


RULES: tuple[MitreRule, ...] = (
    # --- Initial access -------------------------------------------------------------
    MitreRule("T1566.001", (r"spear-?phishing attachment", r"malicious attachment", r"(?:html|pdf|zip|iso|office|word|excel)\s+attachment",
                            r"attachment\s+(?:named|called|contained|opened)", r"attached (?:document|file|invoice)",
                            r"\.(?:html|docm|xlsm|iso|one|lnk)\b.*?(?:attach|email)"),
              0.7, "Phishing email carrying a malicious attachment."),
    MitreRule("T1566.002", (r"spear-?phishing link", r"phishing (?:email|message|page|site|link|kit)s?", r"link (?:pointed|led|redirect)",
                            r"(?:clicked|click) (?:on )?(?:the |a )?link", r"lookalike (?:domain|portal|page)",
                            r"credential harvesting", r"fake (?:login|sign-in|portal|webmail)", r"cloned .*?(?:page|portal)"),
              0.65, "Phishing message containing a link to attacker-controlled content."),
    MitreRule("T1566.003", (r"(?:chat|teams|slack|social media|linkedin|messaging) messages? .*?(?:phish|link|credential)",
                            r"phishing (?:through|via) (?:chat|collaboration|social)", r"external (?:tenants?|chat)"),
              0.6, "Phishing delivered through a third-party service (chat, social network)."),
    MitreRule("T1566.004", (r"voice phishing", r"\bvishing\b", r"callers? impersonat", r"phone call.*?impersonat"),
              0.7, "Phishing conducted over voice calls."),
    MitreRule("T1598.003", (r"(?:collect|harvest|steal)\w* (?:credentials|information)", r"questionnaire", r"recovery phrase",
                            r"identity verification"),
              0.45, "Phishing aimed at eliciting information (credentials, personal data)."),
    MitreRule("T1190", (r"exploit\w* (?:of )?(?:a |an |the )?(?:public|internet)[- ]facing", r"cve-\d{4}-\d+",
                        r"remote code execution", r"(?:authentication|auth) bypass", r"sql injection", r"command injection",
                        r"path traversal", r"deserializ", r"template injection", r"unauthenticated (?:attackers?|api|remote)",
                        r"vulnerable (?:servers?|instances?|appliances?)"),
              0.6, "Exploitation of a vulnerability in an internet-facing application or appliance."),
    MitreRule("T1133", (r"(?:exposed|internet-facing) (?:remote access|vpn|remote desktop|management interface)",
                        r"remote access services?", r"vpn (?:access|account|credentials)"),
              0.5, "Abuse of external remote services (VPN, remote access)."),
    MitreRule("T1189", (r"watering hole", r"drive-by", r"compromised (?:news )?websites? (?:served|display|host)"),
              0.65, "Drive-by compromise through a compromised website."),
    MitreRule("T1195.002", (r"supply chain", r"trojani[sz]ed (?:software|package|update)", r"(?:public|code) repository .*?(?:package|library)"),
              0.65, "Compromise of a software supply chain."),
    MitreRule("T1078", (r"(?:stolen|valid|compromised|leaked) (?:credentials|accounts?|access keys)", r"reused? (?:the )?(?:stolen )?credentials"),
              0.5, "Use of valid (stolen) accounts."),
    # --- Execution ------------------------------------------------------------------
    MitreRule("T1204.002", (r"(?:user|victim)s? (?:opened|executed|ran|run)", r"enable (?:content|macros?)", r"fake installer",
                            r"run the (?:fake )?installer", r"shortcut file"),
              0.55, "User execution of a malicious file."),
    MitreRule("T1204.001", (r"(?:scan|scanning) (?:a |the )?qr code", r"malicious link", r"clicked? .*?link"),
              0.45, "User execution through a malicious link."),
    MitreRule("T1059.001", (r"powershell",), 0.65, "Use of PowerShell for execution."),
    MitreRule("T1059.003", (r"cmd\.exe", r"windows command shell", r"batch (?:file|script)"), 0.55, "Use of the Windows command shell."),
    MitreRule("T1059.004", (r"(?:shell|bash) script", r"\.sh\b", r"unix shell"), 0.5, "Use of a Unix shell script."),
    MitreRule("T1059.005", (r"\bmacros?\b", r"visual basic", r"\bvba\b", r"\bvbs\b"), 0.55, "Use of Visual Basic / macros."),
    MitreRule("T1059.007", (r"javascript", r"\.js\b"), 0.45, "Use of JavaScript."),
    MitreRule("T1203", (r"exploit\w* (?:for|in) (?:the )?(?:client|browser)", r"browser (?:zero-day|exploit|vulnerability)",
                        r"memory corruption vulnerability"),
              0.6, "Exploitation of a client application to execute code."),
    # --- Persistence / privilege escalation ----------------------------------------
    MitreRule("T1547.001", (r"run (?:registry )?key", r"registry run", r"startup folder"), 0.7, "Persistence via registry Run keys / startup folder."),
    MitreRule("T1053.005", (r"scheduled task",), 0.65, "Persistence or execution via scheduled tasks."),
    MitreRule("T1053.003", (r"\bcron(?: job)?\b", r"crontab"), 0.6, "Persistence via cron jobs."),
    MitreRule("T1505.003", (r"web ?shells?",), 0.75, "Web shell installed on a server."),
    MitreRule("T1068", (r"privilege escalation", r"(?:obtain|gain)\w* (?:system|root) privileges", r"escalate privileges"),
              0.65, "Exploitation of a vulnerability for privilege escalation."),
    MitreRule("T1176.001", (r"browser extensions?",), 0.65, "Malicious browser extension."),
    MitreRule("T1574.001", (r"dll side-?loading", r"side-?load", r"dll hijack"), 0.75, "Hijacking of DLL search order / side-loading."),
    # --- Defense evasion / credential access ----------------------------------------
    MitreRule("T1027", (r"obfuscat", r"packed", r"encoded (?:payload|script|command)"), 0.5, "Obfuscated files or information."),
    MitreRule("T1112", (r"modif\w* registry", r"registry keys?"), 0.45, "Modification of the registry."),
    # ATT&CK v20 moved "Impair Defenses: Disable or Modify Tools" (T1562.001) to T1685
    MitreRule("T1685", (r"disable\w* (?:endpoint protection|antivirus|security tools|edr|defender)",
                        r"prevent security tools", r"impair defen[cs]es"),
              0.6, "Impairment of security defences."),
    MitreRule("T1555.003", (r"browser (?:passwords?|credentials)", r"saved (?:browser )?passwords", r"credentials? from (?:web )?browsers?"),
              0.7, "Credentials stolen from web browsers."),
    MitreRule("T1003", (r"credential dumping", r"dump\w* credentials", r"lsass"), 0.65, "OS credential dumping."),
    MitreRule("T1110.004", (r"credential stuffing", r"(?:reused|leaked|breached) (?:credential|password) (?:lists|pairs|dumps)"),
              0.7, "Credential stuffing (reuse of leaked credential pairs)."),
    MitreRule("T1110", (r"brute[- ]?forc", r"password spraying", r"weak (?:ssh )?passwords", r"default credentials"),
              0.6, "Brute force / guessing of credentials."),
    MitreRule("T1056.001", (r"keylog",), 0.75, "Keylogging."),
    MitreRule("T1557", (r"adversary-in-the-middle", r"\baitm\b", r"reverse-proxy phishing", r"reverse proxy .*?(?:phishing|session)",
                        r"session cookie", r"bypass multi-factor"),
              0.65, "Adversary-in-the-middle to intercept credentials / sessions."),
    MitreRule("T1539", (r"steal\w* (?:the )?session cookies?", r"session (?:cookie|token) (?:theft|stolen)", r"hijack accounts without passwords"),
              0.6, "Theft of web session cookies."),
    MitreRule("T1185", (r"web[- ]injects?", r"browser session hijacking", r"inject\w* fake forms"), 0.65, "Browser session hijacking / web injects."),
    # --- Lateral movement / C2 / exfiltration ---------------------------------------
    MitreRule("T1021.001", (r"remote desktop", r"\brdp\b"), 0.6, "Use of Remote Desktop Protocol."),
    MitreRule("T1210", (r"lateral(?:ly)? .*?exploit", r"exploit\w* .*?(?:to )?move laterally", r"smb vulnerability"),
              0.6, "Exploitation of remote services for lateral movement."),
    MitreRule("T1071.001", (r"over https?", r"https? (?:traffic|requests?|post)", r"web protocols?"), 0.45, "C2 over web protocols."),
    MitreRule("T1573", (r"encrypted (?:protocol|channel|traffic)", r"custom encrypted"), 0.5, "Encrypted command and control channel."),
    MitreRule("T1105", (r"download\w* (?:the |a )?(?:next stage|payload|second stage|backdoor|miner|script)", r"fetch\w* the next stage",
                        r"retriev\w* (?:the )?(?:payload|locker|binary)", r"downloaded from"),
              0.55, "Ingress tool transfer (download of additional tools)."),
    MitreRule("T1219", (r"remote access (?:trojan|tool)", r"\brat\b"), 0.6, "Remote access tools."),
    MitreRule("T1041", (r"exfiltrat\w* .*?(?:c2|command-and-control|c&c)", r"(?:upload|send)s? the archive", r"stolen logs are sent"),
              0.55, "Exfiltration over the C2 channel."),
    MitreRule("T1567.002", (r"exfiltrat\w* to cloud storage", r"cloud storage", r"file-sharing mirror"), 0.55, "Exfiltration to cloud storage."),
    MitreRule("T1567", (r"exfiltrat\w*", r"data theft", r"steal\w* files"), 0.4, "Exfiltration over web service (generic)."),
    # --- Impact -----------------------------------------------------------------------
    MitreRule("T1486", (r"encrypt\w* (?:files|data|servers|disks?|file servers|virtual disks|objects)", r"ransomware",
                        r"ransom note", r"\blocker\b", r"files? (?:were )?(?:renamed|encrypted)"),
              0.7, "Data encrypted for impact (ransomware)."),
    MitreRule("T1490", (r"shadow cop", r"vssadmin", r"delet\w* (?:volume )?(?:shadow|backups?|recovery points?|snapshots)",
                        r"wip\w* backups?", r"destroy\w* backups", r"recovery points"),
              0.75, "Inhibit system recovery (shadow copies / backups removed)."),
    MitreRule("T1489", (r"stop\w* (?:database|backup|the) services?", r"services? (?:were )?stopped", r"shut down virtual machines"),
              0.6, "Service stop before impact."),
    MitreRule("T1485", (r"wiper", r"overwr\w* .*?(?:files|disk)", r"data destruction"), 0.65, "Data destruction."),
    MitreRule("T1561.002", (r"master boot record", r"\bmbr\b", r"disk structure wipe"), 0.7, "Disk structure wipe."),
    MitreRule("T1496", (r"crypto(?:currency)?[- ]?min", r"\bminer\b", r"mining pool"), 0.75, "Resource hijacking (cryptomining)."),
    MitreRule("T1498", (r"denial[- ]of[- ]service", r"\bddos\b", r"traffic floods?"), 0.7, "Network denial of service."),
    # --- Reconnaissance / resource development ---------------------------------------
    MitreRule("T1595.002", (r"vulnerability scanning", r"(?:mass|large-scale) scanning", r"scan\w* for (?:vulnerable|exposed)"),
              0.6, "Active vulnerability scanning."),
    MitreRule("T1583.001", (r"(?:domain|domains) (?:was|were) registered", r"registered (?:two|\d+) days before", r"new lookalike domain"),
              0.5, "Acquisition of domains for operations."),
    MitreRule("T1584.005", (r"botnet",), 0.55, "Use of a botnet."),
)
