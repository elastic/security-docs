---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-potential-persistence-via-time-provider-modification.html
---

# Potential Persistence via Time Provider Modification [prebuilt-rule-8-3-3-potential-persistence-via-time-provider-modification]

Identifies modification of the Time Provider. Adversaries may establish persistence by registering and enabling a malicious DLL as a time provider. Windows uses the time provider architecture to obtain accurate time stamps from other network devices or clients in the network. Time providers are implemented in the form of a DLL file which resides in the System32 folder. The service W32Time initiates during the startup of Windows and loads w32time.dll.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://pentestlab.blog/2019/10/22/persistence-time-providers/](https://pentestlab.blog/2019/10/22/persistence-time-providers/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3728]

```js
registry where event.type:"change" and
  registry.path:"HKLM\\SYSTEM\\*ControlSet*\\Services\\W32Time\\TimeProviders\\*" and
  registry.data.strings:"*.dll"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Time Providers
    * ID: T1547.003
    * Reference URL: [https://attack.mitre.org/techniques/T1547/003/](https://attack.mitre.org/techniques/T1547/003/)



