---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-finder-sync-plugin-registered-and-enabled.html
---

# Finder Sync Plugin Registered and Enabled [prebuilt-rule-8-3-1-finder-sync-plugin-registered-and-enabled]

Finder Sync plugins enable users to extend Finder’s functionality by modifying the user interface. Adversaries may abuse this feature by adding a rogue Finder Plugin to repeatedly execute malicious payloads for persistence.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/specterops/presentations/raw/master/Leo%20Pitt/Hey_Im_Still_in_Here_Modern_macOS_Persistence_SO-CON2020.pdf](https://github.com/specterops/presentations/raw/master/Leo%20Pitt/Hey_Im_Still_in_Here_Modern_macOS_Persistence_SO-CON2020.pdf)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Persistence

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2646]

```js
process where event.type in ("start", "process_started") and process.name : "pluginkit" and
  process.args : "-e" and process.args : "use" and process.args : "-i" and
  not process.args :
  (
    "com.google.GoogleDrive.FinderSyncAPIExtension",
    "com.google.drivefs.findersync",
    "com.boxcryptor.osx.Rednif",
    "com.adobe.accmac.ACCFinderSync",
    "com.microsoft.OneDrive.FinderSync",
    "com.insynchq.Insync.Insync-Finder-Integration",
    "com.box.desktop.findersyncext"
  ) and
  not process.parent.executable : (
    "/Library/Application Support/IDriveforMac/IDriveHelperTools/FinderPluginApp.app/Contents/MacOS/FinderPluginApp"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)



