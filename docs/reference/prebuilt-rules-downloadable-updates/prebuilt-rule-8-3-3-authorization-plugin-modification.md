---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-authorization-plugin-modification.html
---

# Authorization Plugin Modification [prebuilt-rule-8-3-3-authorization-plugin-modification]

Authorization plugins are used to extend the authorization services API and implement mechanisms that are not natively supported by the OS, such as multi-factor authentication with third party software. Adversaries may abuse this feature to persist and/or collect clear text credentials as they traverse the registered plugins during user logon.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.apple.com/documentation/security/authorization_plug-ins](https://developer.apple.com/documentation/security/authorization_plug-ins)
* [https://www.xorrior.com/persistent-credential-theft/](https://www.xorrior.com/persistent-credential-theft/)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Persistence

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3445]

```js
event.category:file and not event.type:deletion and
  file.path:(/Library/Security/SecurityAgentPlugins/* and
  not /Library/Security/SecurityAgentPlugins/TeamViewerAuthPlugin.bundle/*) and
  not process.name:shove and process.code_signature.trusted:true
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

    * Name: Authentication Package
    * ID: T1547.002
    * Reference URL: [https://attack.mitre.org/techniques/T1547/002/](https://attack.mitre.org/techniques/T1547/002/)



