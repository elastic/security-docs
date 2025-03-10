---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-component-object-model-hijacking.html
---

# Component Object Model Hijacking [prebuilt-rule-1-0-2-component-object-model-hijacking]

Identifies Component Object Model (COM) hijacking via registry modification. Adversaries may establish persistence by executing malicious content triggered by hijacked references to COM objects.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/](https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1903]

```js
registry where
 /* uncomment once length is stable length(bytes_written_string) > 0 and */
 (registry.path : "HK*}\\InprocServer32\\" and registry.data.strings: ("scrobj.dll", "C:\\*\\scrobj.dll") and
 not registry.path : "*\\{06290BD*-48AA-11D2-8432-006008C3FBFC}\\*")
 or
 /* in general COM Registry changes on Users Hive is less noisy and worth alerting */
 (registry.path : ("HKEY_USERS\\*Classes\\*\\InprocServer32\\",
                   "HKEY_USERS\\*Classes\\*\\LocalServer32\\",
                   "HKEY_USERS\\*Classes\\*\\DelegateExecute\\",
                   "HKEY_USERS\\*Classes\\*\\TreatAs\\",
                   "HKEY_USERS\\*Classes\\CLSID\\*\\ScriptletURL\\") and
 not (process.executable : "?:\\Program Files*\\Veeam\\Backup and Replication\\Console\\veeam.backup.shell.exe" and
      registry.path : "HKEY_USERS\\S-1-5-21-*_Classes\\CLSID\\*\\LocalServer32\\") and
 /* not necessary but good for filtering privileged installations */
 user.domain != "NT AUTHORITY")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Component Object Model Hijacking
    * ID: T1546.015
    * Reference URL: [https://attack.mitre.org/techniques/T1546/015/](https://attack.mitre.org/techniques/T1546/015/)



