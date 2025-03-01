---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-unusual-service-host-child-process-childless-service.html
---

# Unusual Service Host Child Process - Childless Service [prebuilt-rule-8-2-1-unusual-service-host-child-process-childless-service]

Identifies unusual child processes of Service Host (svchost.exe) that traditionally do not spawn any child processes. This may indicate a code injection or an equivalent form of exploitation.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion
* Privilege Escalation

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2252]



## Rule query [_rule_query_2542]

```js
process where event.type in ("start", "process_started") and
     process.parent.name : "svchost.exe" and

     /* based on svchost service arguments -s svcname where the service is known to be childless */

    process.parent.args : ("WdiSystemHost","LicenseManager",
      "StorSvc","CDPSvc","cdbhsvc","BthAvctpSvc","SstpSvc","WdiServiceHost",
      "imgsvc","TrkWks","WpnService","IKEEXT","PolicyAgent","CryptSvc",
      "netprofm","ProfSvc","StateRepository","camsvc","LanmanWorkstation",
      "NlaSvc","EventLog","hidserv","DisplayEnhancementService","ShellHWDetection",
      "AppHostSvc","fhsvc","CscService","PushToInstall") and

      /* unknown FPs can be added here */

     not process.name : ("WerFault.exe","WerFaultSecure.exe","wermgr.exe") and
     not (process.executable : "?:\\Windows\\System32\\RelPost.exe" and process.parent.args : "WdiSystemHost") and
     not (process.name : "rundll32.exe" and
          process.args : "?:\\WINDOWS\\System32\\winethc.dll,ForceProxyDetectionOnNextRun" and process.parent.args : "WdiServiceHost") and
     not (process.executable : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*", "?:\\Windows\\System32\\Kodak\\kds_i4x50\\lib\\lexexe.exe") and
          process.parent.args : "imgsvc")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)

* Sub-technique:

    * Name: Process Hollowing
    * ID: T1055.012
    * Reference URL: [https://attack.mitre.org/techniques/T1055/012/](https://attack.mitre.org/techniques/T1055/012/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)



