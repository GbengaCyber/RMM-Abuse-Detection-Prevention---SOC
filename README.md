# RMM Abuse Detection & Prevention

Attackers don't always bring their own malware. Sometimes they use yours.

RMM tools like AnyDesk, TeamViewer, NinjaRMM, Kaseya, and Datto are legitimate software. Signed binaries. Trusted by EDR. Whitelisted by default. They generate no malware alerts because they are not malware.

That is exactly why attackers abuse them.

Akira ransomware used this technique across 250+ confirmed breaches and collected $42 million in ransoms. CISA flagged RMM abuse as one of the most common initial access methods used by financially motivated threat groups today. This is not a niche attack. It is happening in healthcare, energy, finance, and nonprofits — anywhere there are endpoints and users who trust a help desk email.

This project documents how I built detection and prevention controls to catch RMM abuse at every stage of the attack, from initial delivery through to containment.


## What This Project Demonstrates

This project documents a layered defense architecture built to detect and prevent
RMM tool abuse, one of the most common techniques used by ransomware groups
including Akira, which used this method across 250 confirmed breaches and
collected $42 million in ransoms.

The core problem: RMM tools are signed, trusted, and whitelisted by default.
EDR generates no alerts because the binary is not malware. Without targeted
controls, an attacker can establish a persistent encrypted remote session in
under 60 seconds with nothing firing.

Six prevention layers are deployed and documented across ASR rules, Defender AV
policy, tamper protection, EDR in block mode, local admin restriction, and
Windows Defender Application Control. Detection is built as a multi-signal KQL
query hunting behaviour, network, and prevalence indicators, deployed as a
scheduled Sentinel analytics rule. In live simulation the consolidated query
returned 14 confirmed hits across network and file system telemetry.

> **Target roles:** SOC Analyst · Detection Engineer · Security Engineer

## What Goes Wrong Without Controls

No ASR rules means a browser spawns an RMM installer and the attacker has a session in under a minute. Nothing fires. No one knows.

No PUA protection means Defender sees AnyDesk, recognises it as legitimate software, and waves it through. The default behaviour is to allow it.

No tamper protection means the attacker runs one command from the RMM session and Defender is disabled. EDR goes blind before ransomware deploys. That single command, with tamper protection off, takes about three seconds.

No EDR in block mode means MDE detects suspicious behaviour but only creates an alert. It does not act. In a busy SOC that alert sits in the queue overnight while the attacker moves freely through the network.

No local admin restriction means one recovered credential works on every machine in the estate. An attacker who compromises one endpoint via the RMM session can authenticate to every other device with the same password. Lateral movement takes minutes.

No detection rules means the RMM tool runs quietly for days. No one is looking for it. The SOC finds out when the ransom note appears.

No application control means a renamed or repackaged RMM binary executes freely
regardless of whether ASR and PUA protection missed it. Without WDAC enforcing
an allowlist at kernel level, an unsigned executable from a user-writable path
runs before any behavioural detection has a chance to fire.


## MITRE ATT&CK Mapping

| ID | Technique | Control That Stops It |
|---|---|---|
| T1566.001 / .002 | Phishing | Safe Links, Safe Attachments, ASR |
| T1105 | Ingress Tool Transfer | ASR — block executable from browser/email |
| T1219 | Remote Access Software | PUA protection, KQL detection |
| T1036 | Masquerading | Behaviour-based KQL, file event detection |
| T1562.001 | Disable or Modify Tools | Tamper protection |
| T1078 | Valid Accounts | Local admin restriction, LAPS |
| T1021 | Remote Services | Network Protection, Conditional Access |
| T1041 | Exfiltration Over C2 | Network Protection block mode |
| T1486 | Data Encrypted for Impact | EDR in block mode, ASR ransomware rule |


## Prevention Controls

The design principle behind every control here is simple. Each layer assumes the one above it already failed. If phishing controls miss the email, ASR rules stop the installer. If ASR misses the binary, PUA protection catches the known RMM tool. If PUA misses it, the KQL detection rule fires on the network connection. If the attacker gets in and tries to disable Defender, tamper protection blocks the command. Each layer is built expecting the previous one to be bypassed.

---
### Layer 1 | ASR Rules

Blocks RMM installers from running when delivered via browser, email, or Office macros. During configuration, two rules were Off by default and one was on Audit. All were reviewed and hardened to Block before deployment. Default configurations are not sufficient for this threat.

<img width="800"  alt="image" src="https://github.com/user-attachments/assets/f8aac156-9dab-4444-8f88-84ec3a5e3141" />

---

### Layer 2 | Defender AV Policy

Enforces consistent AV configuration across every managed endpoint via Intune. Without a managed policy, each device runs whatever configuration it shipped with or whatever a local admin last changed. Attackers specifically look for endpoints with degraded AV.

PUA Protection is set to Block because many RMM tools including AnyDesk and TeamViewer are classified as Potentially Unwanted Applications. With PUA on Block, Defender stops them automatically even when ASR does not catch the install.

Cloud Block Level is set to High because an RMM tool repackaged by an attacker to evade detection is low-prevalence by definition. High cloud block level catches it before signatures exist.

Disable Local Admin Merge is enabled because without it, an attacker with local admin can simply override this policy locally. That one setting is what makes the entire policy enforceable.

---
<img width="800"  alt="image" src="https://github.com/user-attachments/assets/416e0f41-b554-4295-8960-f56ee16f5c68" />

---

### Layer 3 | Tamper Protection

Prevents anyone, including local admins, from disabling or modifying Defender via PowerShell or registry edits. Akira ransomware and most human-operated ransomware groups attempt to kill AV and EDR before encrypting. With tamper protection on, that command fails even with SYSTEM privileges. The attacker cannot blind your defences before they strike.

---
<img width="800"  alt="image" src="https://github.com/user-attachments/assets/d69dac5a-c324-4a4d-b5c4-993dbf2e6838" />

---



### Layer 4 | EDR in Block Mode

Tells MDE to actively remediate threats it detects, even when it is not the primary AV. Many organisations run a third-party AV alongside MDE. If the third-party AV misses a renamed or repackaged RMM binary, MDE detects the behaviour but without EDR in block mode it only alerts. It does not act. EDR in block mode closes that gap. Detection and remediation happen automatically, no analyst intervention required.

---
<img width="800"  alt="image" src="https://github.com/user-attachments/assets/830f2099-5d30-4f76-8632-afd9dae721ef" />

---



### Layer 5 | Local Admin Restriction

The built-in Administrator account is disabled via Intune. Combined with LAPS, every device has a unique rotating local admin password managed centrally. Compromising one machine does not hand over the rest of the estate.

One thing worth noting here. During review, the policy was initially configured to Enable the Administrator account instead of Disable. Caught before deployment and corrected. A misconfiguration like that would have actively increased attack surface rather than reducing it. Configuration review matters as much as configuration deployment.

---
<img width="800"  alt="image" src="https://github.com/user-attachments/assets/125b3488-4b19-48c9-87b6-b60230fb9432" />

---

### Layer 6 — Windows Defender Application Control and App Control for Business

WDAC operates at kernel level and blocks unsigned or untrusted executables before a process is ever created. Unlike ASR rules which target specific behaviours, WDAC enforces an allowlist model — if the binary is not explicitly trusted, it does not run. This is the strongest execution prevention control in the stack and the last line of defence if every other layer is bypassed.

Two complementary policies are deployed.

---

**App Control for Business — Intune endpoint security policy**

Policy creation type is set to Built-in controls. Audit mode is disabled, meaning the policy is in full enforcement and not simply logging. Trust apps from managed installer is enabled, so software deployed via Intune is automatically trusted without manual signing. Trust apps with good reputation is enabled, allowing Microsoft-verified applications through without creating operational friction.

The result is a policy that blocks unknown and unsigned binaries — including renamed or repackaged RMM tools — while remaining manageable in a corporate environment.

---

<img width="800"  alt="image" src="https://github.com/user-attachments/assets/1d847efc-49a0-43cb-830a-2c8bef8fd0f8" />


---

**Block App Execution — Intune assignment**

The Block App Execution profile is assigned to the device group with status Active, confirming the policy reached the endpoint and is enforced. The profile targets Windows 10 and later under Endpoint Security — Attack Surface Reduction.

---

<img width="800"  alt="image" src="https://github.com/user-attachments/assets/9e36d4e2-5629-4274-86b4-53b8a56f037e" />


---

**Microsoft Defender Application Control — device configuration profile**

A separate device configuration profile enforces AppLocker application control set to Enforce Components, Store Apps, and Smartlocker. SmartScreen is turned on and users are blocked from bypassing SmartScreen warnings, closing the gap where a user might click through a browser warning to run an unrecognised executable.

---

<img width="800" alt="image" src="https://github.com/user-attachments/assets/edc71187-6b6d-4d41-9b31-ca06725fcfdb" />

---

Together these policies ensure that an RMM binary delivered via phishing and executed from a user-writable path such as Downloads or Desktop cannot run, regardless of whether it is named AnyDesk.exe or disguised as a Windows system process. A renamed binary with no valid signature, no managed installer origin, and no established reputation is blocked at kernel level before the process starts.

---



## Detection — KQL Query

Filename detection alone is not enough. Attackers rename binaries. AnyDesk.exe becomes svchost32.exe or windowsupdate.exe and a filename-based query misses it completely.

This query hunts three signals that hold up regardless of what the file is called.

Signal 1 is behaviour. An RMM process spawned from a suspicious parent process — Chrome, Edge, Word, PowerShell. Legitimate RMM tools are never launched by browsers or Office apps. Renamed or not, that parent-child relationship is the tell.

Signal 2 is network. An outbound connection to known RMM infrastructure from a non-approved device. The binary name does not matter if the destination is an AnyDesk relay server.

Signal 3 is prevalence. A known RMM binary appearing on an endpoint for the first time. A binary that has never been seen before, appearing suddenly, is always worth investigating.

---

```kql
let RMMProcesses = dynamic([
    "anydesk.exe", "teamviewer.exe", "screenconnect.exe",
    "atera_agent.exe", "splashtop_streamer.exe", "rutserv.exe",
    "fleetdeck-agent.exe", "ateraagent.exe", "netsupport.exe",
    "ninjarmm-agent.exe", "ninjarmmagent.exe",
    "dattoagent.exe", "dattormm.exe",
    "kaseyaagent.exe", "agentmon.exe", "kagent.exe"
]);
let RMMDomains = dynamic([
    "anydesk.com", "teamviewer.com", "screenconnect.com",
    "atera.com", "splashtop.com", "logmein.com",
    "gotomypc.com", "zoho.com", "fixme.it", "rutserv.com",
    "fleetdeck.io", "ninjarmm.com", "rmmservice.com",
    "datto.com", "kaseya.com", "kas.kaseya.net"
]);
let SuspiciousParents = dynamic([
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "winword.exe", "excel.exe", "outlook.exe",
    "powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"
]);
let ApprovedDevices = dynamic(["IT-ADMIN-PC01", "IT-ADMIN-PC02"]);
union
(
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ (RMMProcesses)
    | where InitiatingProcessFileName in~ (SuspiciousParents)
    | project Timestamp, DeviceName, AccountName,
        DetectionType = "Suspicious parent process",
        Evidence = strcat(InitiatingProcessFileName, " -> ", FileName),
        Detail = ProcessCommandLine
),
(
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has_any (RMMDomains)
    | where DeviceName !in (ApprovedDevices)
    | project Timestamp, DeviceName,
        AccountName = InitiatingProcessAccountName,
        DetectionType = "RMM domain connection",
        Evidence = RemoteUrl,
        Detail = InitiatingProcessFileName
),
(
    DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where FileName in~ (RMMProcesses)
    | summarize FirstSeen = min(Timestamp), DeviceCount = dcount(DeviceName)
        by FileName, SHA256
    | project Timestamp = FirstSeen, DeviceName = "multiple",
        AccountName = "N/A",
        DetectionType = "New RMM binary first seen",
        Evidence = FileName,
        Detail = SHA256
)
| order by Timestamp desc
```
---
File installation detection — catches the binary being written to disk independent of process or network telemetry:

```kql
DeviceFileEvents
| where FileName == "AnyDesk.exe"
| where ActionType == "FileCreated"
| project TimeGenerated, RequestAccountName, FileName,
    ActionType, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```
---

## Live Simulation Results

All controls were tested in a controlled Azure lab VM, onboarded to MDE with every policy applied.

Before the simulation, the query returned zero results. Clean environment, nothing running.

<img width="800"  alt="Pasted Graphic 4" src="https://github.com/user-attachments/assets/5ede5c95-83fa-43fb-bcc9-e4f4e997efc7" />

---


To simulate the attack, I connected from the VM to multiple RMM domains via PowerShell, mimicking the outbound beacon behaviour an attacker's RMM session would generate. Then downloaded and installed AnyDesk from the browser, simulating the full phishing delivery chain.

---
<img width="800"  alt="image" src="https://github.com/user-attachments/assets/71d08bd0-70a3-4cdc-84db-232b07481c82" />

---

Anydesk Downloaded and running successfully on VM


<img width="800"  alt="image" src="https://github.com/user-attachments/assets/06c041b5-62d9-4f8d-97b3-398e00243607" />

---


The consolidated query returned 14 hits. Connections to ninjarmm.com, anydesk.com, and teamviewer.com from powershell.exe. Connections to AnyDesk relay servers from msedge.exe during the download. Connections from the AnyDesk binary itself phoning home after installation. Device: soclab. User: labuser1.

<img width="800"  alt="image" src="https://github.com/user-attachments/assets/fb3b4028-aead-4427-ae5f-7785d3f4ca97" />

--


A separate file event query confirmed AnyDesk.exe written to C:\Program Files (x86) at 5:23am, captured at the file system level independent of network telemetry.

---
<img width="800"  alt="image" src="https://github.com/user-attachments/assets/88293a2a-4ed2-47c0-906d-daa8f9b98c0e" />

---


## Sentinel Analytics Rule

The KQL query is deployed as a scheduled Sentinel analytics rule running every hour across the last 24 hours of telemetry. Any result triggers a High severity incident assigned directly to the analyst queue.

Detection is not dependent on someone remembering to run a hunt. An attacker who installs an RMM tool at 3am gets caught at 3am. The incident is waiting when the analyst starts their shift.

Rule: High severity. Runs every 1 hour. MITRE tactics mapped across Initial Access, Execution, Persistence, Defence Evasion, Lateral Movement, Exfiltration, and Impact.

---
<img width="800"  alt="Pasted Graphic 3" src="https://github.com/user-attachments/assets/844f0ce3-2f91-490e-904e-00f0a3358d21" />

---

## Response Playbook

When the rule fires, the first question is which signal triggered it. That tells you how far into the chain the attacker is.

Check the DeviceName and AccountName. Has the same user triggered alerts on other devices in the last 30 minutes? If yes, lateral movement may already be underway.

Isolate the device via MDE immediately. Do not wait for confirmation. Every minute of delay is time the attacker uses to move.

Kill the RMM session and remove the binary. Revoke all active sessions for the affected account in Entra ID. Reset credentials. Check whether any new accounts were created during the session window, attackers frequently create backdoor accounts before deploying ransomware.

Run the domain connection query across all devices. One hit almost always means more. Look for the same RMM domains appearing on other endpoints in the same timeframe.

Document everything. Incident timeline, IOCs extracted, controls that fired, controls that missed. Written clearly enough that a non-technical stakeholder understands what happened and what changed as a result.

Then harden. Add any new domains or hashes to the detection list. If a control was bypassed, document how and update the rule. Every incident is a lesson. Every lesson becomes a control.


## References

- [CISA AA23-025A — Malicious Use of RMM Tools](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a)
- [CISA AA24-109A — Akira Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a)
- [MITRE T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [Microsoft ASR Rules Reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft EDR in Block Mode](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/edr-in-block-mode)
