---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-microsoft-exchange-server-um-writing-suspicious-files.html
---

# Microsoft Exchange Server UM Writing Suspicious Files [prebuilt-rule-8-4-2-microsoft-exchange-server-um-writing-suspicious-files]

Identifies suspicious files being written by the Microsoft Exchange Server Unified Messaging (UM) service. This activity has been observed exploiting CVE-2021-26858.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers)
* [https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Initial Access

**Version**: 101

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3488]

## Triage and analysis

Positive hits can be checked against the established Microsoft [baselines](https://github.com/microsoft/CSS-Exchange/tree/main/Security/Baselines).

Microsoft highly recommends that the best course of action is patching, but this may not protect already compromised systems
from existing intrusions. Other tools for detecting and mitigating can be found within their Exchange support
[repository](https://github.com/microsoft/CSS-Exchange/tree/main/Security)

## Rule query [_rule_query_4154]

```js
file where event.type == "creation" and
  process.name : ("UMWorkerProcess.exe", "umservice.exe") and
  file.extension : ("php", "jsp", "js", "aspx", "asmx", "asax", "cfm", "shtml") and
  (
    file.path : "?:\\inetpub\\wwwroot\\aspnet_client\\*" or

    (file.path : "?:\\*\\Microsoft\\Exchange Server*\\FrontEnd\\HttpProxy\\owa\\auth\\*" and
       not (file.path : "?:\\*\\Microsoft\\Exchange Server*\\FrontEnd\\HttpProxy\\owa\\auth\\version\\*" or
            file.name : ("errorFE.aspx", "expiredpassword.aspx", "frowny.aspx", "GetIdToken.htm", "logoff.aspx",
                        "logon.aspx", "OutlookCN.aspx", "RedirSuiteServiceProxy.aspx", "signout.aspx"))) or

    (file.path : "?:\\*\\Microsoft\\Exchange Server*\\FrontEnd\\HttpProxy\\ecp\\auth\\*" and
       not file.name : "TimeoutLogoff.aspx")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Exploit Public-Facing Application
    * ID: T1190
    * Reference URL: [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)



