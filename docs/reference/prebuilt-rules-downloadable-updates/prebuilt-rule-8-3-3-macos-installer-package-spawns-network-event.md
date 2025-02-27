---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-macos-installer-package-spawns-network-event.html
---

# MacOS Installer Package Spawns Network Event [prebuilt-rule-8-3-3-macos-installer-package-spawns-network-event]

Detects the execution of a MacOS installer package with an abnormal child process (e.g bash) followed immediately by a network connection via a suspicious process (e.g curl). Threat actors will build and distribute malicious MacOS installer packages, which have a .pkg extension, many times imitating valid software in order to persuade and infect their victims often using the package files (e.g pre/post install scripts etc.) to download additional tools or malicious software. If this rule fires it should indicate the installation of a malicious or suspicious package.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://redcanary.com/blog/clipping-silver-sparrows-wings](https://redcanary.com/blog/clipping-silver-sparrows-wings)
* [https://posts.specterops.io/introducing-mystikal-4fbd2f7ae520](https://posts.specterops.io/introducing-mystikal-4fbd2f7ae520)
* [https://github.com/D00MFist/Mystikal](https://github.com/D00MFist/Mystikal)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Execution
* Command and Control

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3432]

```js
sequence by host.id, user.id with maxspan=30s
[process where event.type == "start" and event.action == "exec" and process.parent.name : ("installer", "package_script_service") and process.name : ("bash", "sh", "zsh", "python", "osascript", "tclsh*")]
[network where event.type == "start" and process.name : ("curl", "osascript", "wget", "python")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: JavaScript
    * ID: T1059.007
    * Reference URL: [https://attack.mitre.org/techniques/T1059/007/](https://attack.mitre.org/techniques/T1059/007/)

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Application Layer Protocol
    * ID: T1071
    * Reference URL: [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)

* Sub-technique:

    * Name: Web Protocols
    * ID: T1071.001
    * Reference URL: [https://attack.mitre.org/techniques/T1071/001/](https://attack.mitre.org/techniques/T1071/001/)



