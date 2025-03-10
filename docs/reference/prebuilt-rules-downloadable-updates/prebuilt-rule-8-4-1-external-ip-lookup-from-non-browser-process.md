---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-external-ip-lookup-from-non-browser-process.html
---

# External IP Lookup from Non-Browser Process [prebuilt-rule-8-4-1-external-ip-lookup-from-non-browser-process]

Identifies domains commonly used by adversaries for post-exploitation IP lookups. It is common for adversaries to test for Internet access and acquire their external IP address after they have gained access to a system. Among others, this has been observed in campaigns leveraging the information stealer, Trickbot.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://community.jisc.ac.uk/blogs/csirt/article/trickbot-analysis-and-mitigation](https://community.jisc.ac.uk/blogs/csirt/article/trickbot-analysis-and-mitigation)
* [https://www.cybereason.com/blog/dropping-anchor-from-a-trickbot-infection-to-the-discovery-of-the-anchor-malware](https://www.cybereason.com/blog/dropping-anchor-from-a-trickbot-infection-to-the-discovery-of-the-anchor-malware)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Discovery
* Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2777]

## Triage and analysis

## Investigating External IP Lookup from Non-Browser Process

After successfully compromising an environment, attackers may try to gain situational awareness to plan their next steps.
This can happen by running commands to enumerate network resources, users, connections, files, and installed security
software.

This rule looks for connections to known IP lookup services through non-browser processes or non-installed programs.
Using only the IP address of the compromised system, attackers can obtain valuable information such as the system's
geographic location, the company that owns the IP, whether the system is cloud-hosted, and more.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Investigate abnormal behaviors observed by the subject process, such as network connections, registry or file
modifications, and any spawned child processes.

## False positive analysis

- Discovery activities are not inherently malicious if they occur in isolation. As long as the analyst did not identify
suspicious activity related to the user or host, such alerts can be dismissed.
- If this rule is noisy in your environment due to expected activity, consider adding exceptions — preferably with a combination
of user and command line conditions.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Use the data collected through the analysis to investigate other machines affected in the environment.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_3175]

```js
network where network.protocol == "dns" and
    process.name != null and user.id not in ("S-1-5-19", "S-1-5-20") and
    event.action == "lookup_requested" and
    /* Add new external IP lookup services here */
    dns.question.name :
    (
        "*api.ipify.org",
        "*freegeoip.app",
        "*checkip.amazonaws.com",
        "*checkip.dyndns.org",
        "*freegeoip.app",
        "*icanhazip.com",
        "*ifconfig.*",
        "*ipecho.net",
        "*ipgeoapi.com",
        "*ipinfo.io",
        "*ip.anysrc.net",
        "*myexternalip.com",
        "*myipaddress.com",
        "*showipaddress.com",
        "*whatismyipaddress.com",
        "*wtfismyip.com",
        "*ipapi.co",
        "*ip-lookup.net",
        "*ipstack.com"
    ) and
    /* Insert noisy false positives here */
    not process.executable :
    (
      "?:\\Program Files\\*.exe",
      "?:\\Program Files (x86)\\*.exe",
      "?:\\Windows\\System32\\WWAHost.exe",
      "?:\\Windows\\System32\\smartscreen.exe",
      "?:\\Windows\\System32\\MicrosoftEdgeCP.exe",
      "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
      "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
      "?:\\Users\\*\\AppData\\Local\\Programs\\Fiddler\\Fiddler.exe",
      "?:\\Users\\*\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
      "?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Location Discovery
    * ID: T1614
    * Reference URL: [https://attack.mitre.org/techniques/T1614/](https://attack.mitre.org/techniques/T1614/)

* Technique:

    * Name: System Network Configuration Discovery
    * ID: T1016
    * Reference URL: [https://attack.mitre.org/techniques/T1016/](https://attack.mitre.org/techniques/T1016/)

* Sub-technique:

    * Name: Internet Connection Discovery
    * ID: T1016.001
    * Reference URL: [https://attack.mitre.org/techniques/T1016/001/](https://attack.mitre.org/techniques/T1016/001/)



