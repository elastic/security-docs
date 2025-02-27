---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-unusual-child-process-of-dns-exe.html
---

# Unusual Child Process of dns.exe [prebuilt-rule-1-0-2-unusual-child-process-of-dns-exe]

Identifies an unexpected process spawning from dns.exe, the process responsible for Windows DNS server services, which may indicate activity related to remote code execution or other forms of exploitation.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/](https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/)
* [https://msrc-blog.microsoft.com/2020/07/14/july-2020-security-update-cve-2020-1350-vulnerability-in-windows-domain-name-system-dns-server/](https://msrc-blog.microsoft.com/2020/07/14/july-2020-security-update-cve-2020-1350-vulnerability-in-windows-domain-name-system-dns-server/)
* [https://github.com/maxpl0it/CVE-2020-1350-DoS](https://github.com/maxpl0it/CVE-2020-1350-DoS)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Initial Access

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1617]

## Triage and analysis

## Investigating Unusual Child Process
Detection alerts from this rule indicate potential suspicious child processes spawned after exploitation from CVE-2020-1350 (SigRed) has occurred. Here are some possible avenues of investigation:
- Any suspicious or abnormal child process spawned from dns.exe should be reviewed and investigated with care. It's impossible to predict what an adversary may deploy as the follow-on process after the exploit, but built-in discovery/enumeration utilities should be top of mind (whoami.exe, netstat.exe, systeminfo.exe, tasklist.exe).
- Built-in Windows programs that contain capabilities used to download and execute additional payloads should also be considered. This is not an exhaustive list, but ideal candidates to start out would be: mshta.exe, powershell.exe, regsvr32.exe, rundll32.exe, wscript.exe, wmic.exe.
- If the DoS exploit is successful and DNS Server service crashes, be mindful of potential child processes related to werfault.exe occurring.
- Any subsequent activity following the child process spawned related to execution/network activity should be thoroughly reviewed from the endpoint.

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1866]

```js
process where event.type == "start" and process.parent.name : "dns.exe" and
  not process.name : "conhost.exe"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: External Remote Services
    * ID: T1133
    * Reference URL: [https://attack.mitre.org/techniques/T1133/](https://attack.mitre.org/techniques/T1133/)



