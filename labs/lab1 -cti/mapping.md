# MITRE ATT&CK Mapping

| Tactic | ID | Technique | Evidence / rationale | Confidence |
|---|---|---|---|---|
| Reconnaissance | T1589.003 | Gather Victim Identity Information: Employee Names | The actor researched relevant prominent people and approached selected targets under a trusted identity. | Medium |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Fake Teams meeting invitations directed targets into a device-code authentication flow. ATT&CK explicitly includes device-code phishing under this sub-technique. | High |
| Credential Access | T1528 | Steal Application Access Token | The victim’s authorization produced access and refresh tokens that became available to the actor. | High |
| Defense Evasion / Persistence / Privilege Escalation / Initial Access | T1078.004 | Valid Accounts: Cloud Accounts | The stolen valid session was used to access Microsoft 365 resources as the compromised user. | High |
| Lateral Movement | T1534 | Internal Spearphishing | The actor sent additional device-code phishing messages from a compromised user’s account to other users in the organization. | High |
| Collection | T1114.002 | Email Collection: Remote Email Collection | Microsoft Graph was used to search mailboxes and collect email remotely. | High |
| Command and Control | T1090 | Proxy | Regionally appropriate proxies were used to conceal suspicious sign-in activity. | High |

The mapping is an analyst assessment based on the Microsoft report and MITRE ATT&CK definitions.
