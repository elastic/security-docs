---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-lsa-authentication-package-abuse.html
---

# Potential LSA Authentication Package Abuse [prebuilt-rule-8-17-4-potential-lsa-authentication-package-abuse]

Adversaries can use the autostart mechanism provided by the Local Security Authority (LSA) authentication packages for privilege escalation or persistence by placing a reference to a binary in the Windows registry. The binary will then be executed by SYSTEM when the authentication packages are loaded.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* endgame-*
* logs-m365_defender.event-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Microsoft Defender for Endpoint
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4962]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential LSA Authentication Package Abuse**

The Local Security Authority (LSA) in Windows manages authentication and security policies. Adversaries exploit LSA by modifying registry paths to include malicious binaries, which are executed with SYSTEM privileges during authentication package loading. The detection rule identifies unauthorized registry changes by non-SYSTEM users, signaling potential privilege escalation or persistence attempts.

**Possible investigation steps**

* Review the registry change event details to identify the specific binary path added to the LSA Authentication Packages registry key.
* Investigate the user account associated with the registry change event to determine if it is a legitimate user or potentially compromised.
* Check the timestamp of the registry modification to correlate with any other suspicious activities or events on the system around the same time.
* Analyze the binary referenced in the registry change for any known malicious signatures or behaviors using antivirus or threat intelligence tools.
* Examine system logs and security events for any signs of privilege escalation or persistence techniques used by the adversary.
* Assess the system for any additional unauthorized changes or indicators of compromise that may suggest further malicious activity.

**False positive analysis**

* Legitimate software installations or updates may modify the LSA authentication package registry path. Users should verify if recent installations or updates coincide with the detected changes and consider excluding these specific software processes if they are deemed safe.
* System administrators or IT management tools might perform authorized changes to the registry for maintenance or configuration purposes. Users can create exceptions for known administrative tools or processes that are regularly used for legitimate system management tasks.
* Security software or endpoint protection solutions may alter the registry as part of their normal operation. Users should identify and whitelist these security applications to prevent unnecessary alerts.
* Custom scripts or automation tools used within the organization might inadvertently trigger this rule. Users should review and document these scripts, ensuring they are secure, and exclude them if they are confirmed to be non-threatening.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes associated with the unauthorized registry change to halt potential malicious activity.
* Restore the modified registry path to its original state by removing any unauthorized entries in the LSA Authentication Packages registry key.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malicious binaries or remnants.
* Review and reset credentials for any accounts that may have been compromised, focusing on those with elevated privileges.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for registry changes, particularly those involving LSA authentication packages, to detect and respond to similar threats in the future.


## Rule query [_rule_query_5917]

```js
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
      "HKLM\\SYSTEM\\*ControlSet*\\Control\\Lsa\\Authentication Packages",
      "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Lsa\\Authentication Packages"
  ) and
  /* exclude SYSTEM SID - look for changes by non-SYSTEM user */
  not user.id : "S-1-5-18"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Authentication Package
    * ID: T1547.002
    * Reference URL: [https://attack.mitre.org/techniques/T1547/002/](https://attack.mitre.org/techniques/T1547/002/)

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



