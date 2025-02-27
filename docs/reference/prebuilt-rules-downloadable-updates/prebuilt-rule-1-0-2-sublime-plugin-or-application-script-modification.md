---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-sublime-plugin-or-application-script-modification.html
---

# Sublime Plugin or Application Script Modification [prebuilt-rule-1-0-2-sublime-plugin-or-application-script-modification]

Adversaries may create or modify the Sublime application plugins or scripts to execute a malicious payload each time the Sublime application is started.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5](https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Persistence

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1486]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1721]

```js
file where event.type in ("change", "creation") and file.extension : "py" and
  file.path :
    (
      "/Users/*/Library/Application Support/Sublime Text*/Packages/*.py",
      "/Applications/Sublime Text.app/Contents/MacOS/sublime.py"
    ) and
  not process.executable :
    (
      "/Applications/Sublime Text*.app/Contents/MacOS/Sublime Text*",
      "/usr/local/Cellar/git/*/bin/git",
      "/usr/libexec/xpcproxy",
      "/System/Library/PrivateFrameworks/DesktopServicesPriv.framework/Versions/A/Resources/DesktopServicesHelper",
      "/Applications/Sublime Text.app/Contents/MacOS/plugin_host"
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Compromise Client Software Binary
    * ID: T1554
    * Reference URL: [https://attack.mitre.org/techniques/T1554/](https://attack.mitre.org/techniques/T1554/)



