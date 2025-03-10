---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-chkconfig-service-add.html
---

# Chkconfig Service Add [prebuilt-rule-8-4-2-chkconfig-service-add]

Detects the use of the chkconfig binary to manually add a service for management by chkconfig. Threat actors may utilize this technique to maintain persistence on a system. When a new service is added, chkconfig ensures that the service has either a start or a kill entry in every runlevel and when the system is rebooted the service file added will run providing long-term persistence.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/](https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Persistence
* Lightning Framework

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3887]

```js
process where event.type == "start" and
   (process.executable : "/usr/sbin/chkconfig" and process.args : "--add") or
   (process.args : "*chkconfig" and process.args : "--add")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Initialization Scripts
    * ID: T1037
    * Reference URL: [https://attack.mitre.org/techniques/T1037/](https://attack.mitre.org/techniques/T1037/)

* Sub-technique:

    * Name: RC Scripts
    * ID: T1037.004
    * Reference URL: [https://attack.mitre.org/techniques/T1037/004/](https://attack.mitre.org/techniques/T1037/004/)



