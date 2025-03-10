---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-potential-persistence-via-atom-init-script-modification.html
---

# Potential Persistence via Atom Init Script Modification [prebuilt-rule-8-4-2-potential-persistence-via-atom-init-script-modification]

Identifies modifications to the Atom desktop text editor Init File. Adversaries may add malicious JavaScript code to the init.coffee file that will be executed upon the Atom application opening.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/D00MFist/PersistentJXA/blob/master/AtomPersist.js](https://github.com/D00MFist/PersistentJXA/blob/master/AtomPersist.js)
* [https://flight-manual.atom.io/hacking-atom/sections/the-init-file/](https://flight-manual.atom.io/hacking-atom/sections/the-init-file/)

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

## Rule query [_rule_query_3953]

```js
event.category:"file" and not event.type:"deletion" and
 file.path:/Users/*/.atom/init.coffee and not process.name:(Atom or xpcproxy) and not user.name:root
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



