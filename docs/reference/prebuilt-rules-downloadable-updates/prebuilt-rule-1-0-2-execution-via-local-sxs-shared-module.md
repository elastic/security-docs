---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-execution-via-local-sxs-shared-module.html
---

# Execution via local SxS Shared Module [prebuilt-rule-1-0-2-execution-via-local-sxs-shared-module]

Identifies the creation, change, or deletion of a DLL module within a Windows SxS local folder. Adversaries may abuse shared modules to execute malicious payloads by instructing the Windows module loader to load DLLs from arbitrary local paths.

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

* [https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Execution

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1594]

## Triage and analysis

The SxS DotLocal folder is a legitimate feature that can be abused to hijack standard modules loading order by forcing an executable on the same application.exe.local folder to load a malicious DLL module from the same directory.

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1843]

```js
file where file.extension : "dll" and file.path : "C:\\*\\*.exe.local\\*.dll"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Shared Modules
    * ID: T1129
    * Reference URL: [https://attack.mitre.org/techniques/T1129/](https://attack.mitre.org/techniques/T1129/)



