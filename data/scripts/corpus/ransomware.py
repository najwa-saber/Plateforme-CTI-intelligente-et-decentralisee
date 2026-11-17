# Synthetic CTI corpus - category: ransomware (fictitious families "NightVault", "LockMare", "Glacier", ...)

REPORTS = [
    dict(id="CTI-021", campaign="RW-C1", mitre=["T1486", "T1490", "T1567.002"], ambiguous=False, published="2026-02-20",
         title="NightVault ransomware intrusion at a regional hospital",
         text="""The NightVault operators encrypted file servers of a regional hospital after a two-week dwell time.
Before encryption, they deleted volume shadow copies with vssadmin and stopped backup services. Around 300 GB of
data were exfiltrated to cloud storage, then a ransom note threatened publication on a leak site. The encryptor
binary had SHA-256 <<sha256|@nightvault-enc>> and appended the extension .nvault to files. Command-and-control
traffic was observed to <<ipv4|198.51.100.77>>."""),
    dict(id="CTI-022", campaign="RW-C1", mitre=["T1486", "T1490"], ambiguous=False, published="2026-03-04",
         title="NightVault affiliate playbook",
         text="""Analysis of a leaked NightVault affiliate playbook shows a standard double-extortion workflow:
initial access is bought from brokers, domain admin rights are obtained, backups are destroyed and the locker is
deployed through group policy. The playbook references the negotiation portal
<<domain|nvault7xk2qpl4mzd3r5t6y7u8i9o0p1a2s3d4f5g6h7j8k9l0zxcv.onion>> and the staging server <<ipv4|198.51.100.77>>.
Affiliates receive 80 percent of the ransom payment, which is requested in cryptocurrency."""),
    dict(id="CTI-023", campaign="RW-C2", mitre=["T1486", "T1566.001", "T1059.001"], ambiguous=True, published="2026-02-25",
         title="LockMare ransomware delivered after payroll phishing",
         text="""A transport company was hit by LockMare ransomware. Initial access came from the payroll phishing
campaign, the employee's stolen credentials being reused on the VPN from <<ipv4|198.51.100.24>>. The operators
used PowerShell to disable endpoint protection and deployed the locker (MD5 <<md5|@lockmare-locker>>) on every
server. Files were renamed with the .lmare extension and the ransom note pointed to <<domain|lockmare-pay.test>>.
Encryption of the ERP database halted operations for four days."""),
    dict(id="CTI-024", campaign="RW-C2", mitre=["T1486", "T1490"], ambiguous=False, published="2026-03-15",
         title="LockMare encryptor technical analysis",
         text="""The LockMare encryptor uses a hybrid scheme: each file is encrypted with a random symmetric key which
is then protected with the operator's public key. It skips system folders to keep the machine bootable, deletes
shadow copies and empties the recycle bin. The sample analysed (MD5 <<md5|@lockmare-locker>>, SHA-256
<<sha256|@lockmare-locker-256>>) contains a hardcoded payment page <<url|http://lockmare-pay.test/victim/portal>>.
No decryption flaw was identified."""),
    dict(id="CTI-025", campaign="RW-C3", mitre=["T1486", "T1133"], ambiguous=False, published="2026-04-18",
         title="Glacier ransomware targeting virtualisation hosts",
         text="""Glacier, a Linux variant of a ransomware family, targets hypervisors. Attackers log in through exposed
remote access services with stolen credentials, shut down virtual machines and encrypt the disk images. The
encryptor (SHA-256 <<sha256|@glacier-esxi>>) is downloaded from <<url|hxxp://203.0.113[.]99/g.sh|http://203.0.113.99/g.sh>>.
Entire clusters become unavailable in minutes, which multiplies the impact compared with workstation encryption.
Victims should restrict management interfaces to dedicated networks."""),
    dict(id="CTI-026", campaign="RW-C1", mitre=["T1486", "T1567.002"], ambiguous=False, published="2026-04-29",
         title="Data leak site publishes NightVault victims",
         text="""The NightVault leak site listed eleven new victims this month, including a law firm and two
municipalities. Stolen archives are published when the ransom deadline expires. The group uses a file-sharing
mirror at <<domain|nv-files-mirror.example>> to distribute archives. Negotiators demand payment within seven days
and threaten to contact customers of the victim. The encryption component is unchanged since February."""),
    dict(id="CTI-027", campaign="RW-C4", mitre=["T1486", "T1190"], ambiguous=True, published="2026-05-06",
         title="Ransomware deployed after VPN appliance exploitation",
         text="""Operators of the Shardlock ransomware gained access by exploiting an unpatched VPN appliance, then
moved laterally with remote desktop and encrypted 400 workstations over a weekend. The exploitation is only the
entry point; the report focuses on the encryption and extortion phase. The locker (SHA-256 <<sha256|@shardlock>>)
communicates with <<ipv4|192.0.2.177>> to register the victim and retrieve the public key. A ransom of 40 bitcoin
was requested."""),
    dict(id="CTI-028", campaign="RW-C5", mitre=["T1486", "T1490", "T1489"], ambiguous=False, published="2026-05-21",
         title="Ransomware incident at a manufacturing plant",
         text="""Production lines stopped after a ransomware attack encrypted the engineering workstations. The attackers
stopped database and backup services before launching the encryption, then left a note named RESTORE-FILES.txt.
Investigation found the binary svchosts.exe with MD5 <<md5|@mfg-locker>>. Network logs showed outbound traffic to
<<domain|restore-files-help.invalid>> and <<ipv4|198.51.100.230>>. The company restored from offline backups and did
not pay."""),
    dict(id="CTI-029", campaign="RW-C3", mitre=["T1486"], ambiguous=False, published="2026-06-09",
         title="Glacier ransomware new Linux build",
         text="""A new build of the Glacier Linux locker adds intermittent encryption: only parts of each large file are
encrypted to speed up the attack. The binary (SHA-256 <<sha256|@glacier-esxi-v2>>) is still retrieved from
<<ipv4|203.0.113.99>>. The ransom note now includes a chat identifier and a deadline of 72 hours. Hypervisor
administrators should disable unnecessary shell access."""),
    dict(id="CTI-030", campaign="RW-C6", mitre=["T1486", "T1490"], ambiguous=False, published="2026-06-30",
         title="Education sector ransomware wave",
         text="""Several universities reported encrypted file shares and wiped backups at the start of the summer
holidays, when staffing is reduced. The ransom notes referred to a group calling itself Paper Owl and demanded
payment to <<url|https://paperowl-support.example/chat>>. Files received the extension .owl. The encryptor hash is
<<sha256|@paperowl>>. The attacks are attributed to the same affiliate based on identical tooling."""),
    dict(id="CTI-031", campaign="RW-C2", mitre=["T1486", "T1567"], ambiguous=False, published="2026-07-10",
         title="LockMare exfiltration tooling",
         text="""Before deploying LockMare, the affiliates exfiltrate data with a renamed sync utility to
<<ipv4|198.51.100.88>>. The extortion note claims the publication of stolen documents on
<<domain|lockmare-pay.test>> if no payment is received. Investigators recovered the locker with MD5
<<md5|@lockmare-locker>> on three domain controllers. Victims are mainly logistics and transport companies."""),
    dict(id="CTI-032", campaign="RW-C7", mitre=["T1486", "T1078"], ambiguous=False, published="2026-07-25",
         title="Cloud storage encryption by ransomware actor",
         text="""An actor used compromised cloud access keys to encrypt objects stored in buckets with server-side keys
under his control, then deleted the original versions. The ransom note was uploaded as a text object in every
bucket and requested contact through <<domain|bucket-recovery-desk.test>>. API calls originated from
<<ipv4|203.0.113.140>>. This cloud-native extortion does not require any malware on endpoints."""),
    dict(id="CTI-033", campaign="RW-C1", mitre=["T1486", "T1490"], ambiguous=False, published="2026-08-12",
         title="NightVault decryptor reliability issues",
         text="""Victims who paid the NightVault ransom reported that the decryptor failed on large databases, leaving
files corrupted. Incident responders recommend testing decryptors on copies only. The encryptor sample
<<sha256|@nightvault-enc>> is still used by most affiliates, and the C2 <<ipv4|198.51.100.77>> remains active."""),
    dict(id="CTI-034", campaign="RW-C8", mitre=["T1486", "T1021.001"], ambiguous=False, published="2026-08-26",
         title="Ransomware spread through remote desktop",
         text="""Attackers brute-forced an internet-facing remote desktop server, created a local administrator and
spread to the file servers. A locker dubbed Mirelock encrypted 2 TB of documents. The binary MD5 is
<<md5|@mirelock>>. The note directed victims to <<url|http://mirelock-decrypt.test/id>>. Remote desktop exposure
remains a frequent root cause of ransomware incidents in small organisations."""),
    dict(id="CTI-035", campaign="RW-C9", mitre=["T1486", "T1490"], ambiguous=False, published="2026-09-04",
         title="Healthcare ransomware attack disrupts appointments",
         text="""A clinic network cancelled appointments after its scheduling system was encrypted. The attackers wiped
backup snapshots and left a note signed by the Cobalt Mantis group. Payment instructions referred to
<<domain|cobaltmantis-pay.example>>. The encryptor SHA-256 is <<sha256|@cobaltmantis>>. Patient data theft is
under investigation, and authorities have been notified."""),
    dict(id="CTI-036", campaign="RW-C4", mitre=["T1486"], ambiguous=False, published="2026-09-18",
         title="Shardlock ransomware leak site analysis",
         text="""The Shardlock group published a leak site listing victims from retail and hospitality. The site
mirrors are hosted at <<ipv4|192.0.2.177>> and <<ipv4|192.0.2.178>>. Shardlock demands ransoms proportional to the
victim revenue and offers a discount for fast payment. The encryptor <<sha256|@shardlock>> has not changed."""),
    dict(id="CTI-037", campaign="RW-C10", mitre=["T1486", "T1490", "T1112"], ambiguous=False, published="2026-10-02",
         title="Ransomware using safe mode reboot",
         text="""A ransomware strain called Hollowkey reboots Windows machines into safe mode to prevent security tools
from starting, then encrypts files. It modifies registry keys to ensure execution in safe mode and deletes
recovery points. The sample MD5 is <<md5|@hollowkey>> and its configuration contains the contact address on
<<domain|hollowkey-recovery.test>>. Encrypted files end with .hkey."""),
    dict(id="CTI-038", campaign="RW-C6", mitre=["T1486"], ambiguous=False, published="2026-10-16",
         title="Paper Owl ransomware hits a city council",
         text="""The Paper Owl group encrypted the servers of a city council, disrupting online services for citizens.
The ransom note again pointed to <<url|https://paperowl-support.example/chat>>. The locker hash <<sha256|@paperowl>>
matches earlier education-sector incidents. The council refused to pay and rebuilt its environment."""),
    dict(id="CTI-039", campaign="RW-C11", mitre=["T1486", "T1490"], ambiguous=False, published="2026-10-30",
         title="Ransomware-as-a-service recruitment post",
         text="""On a criminal forum, the operators of a new ransomware-as-a-service called Ember Fox advertised for
affiliates experienced in network intrusion. They offer a Windows and Linux locker, a leak site and a
negotiation team. Their panel was hosted at <<ipv4|203.0.113.222>>. Test samples shared with affiliates include
<<sha256|@emberfox>>. Encryption speed is presented as the main selling point."""),
    dict(id="CTI-040", campaign="RW-C3", mitre=["T1486", "T1133"], ambiguous=False, published="2026-11-06",
         title="Glacier operators exploit weak hypervisor passwords",
         text="""Glacier operators continue to target virtualisation clusters, this time using weak passwords on
management interfaces exposed to the internet. After logging in, they encrypt virtual disks with the locker
downloaded from <<url|http://203.0.113.99/g.sh>>. Victims include two hosting providers, which affected hundreds
of downstream customers."""),
]
