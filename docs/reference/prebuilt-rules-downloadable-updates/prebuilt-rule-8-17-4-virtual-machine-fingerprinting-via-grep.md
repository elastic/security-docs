---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-virtual-machine-fingerprinting-via-grep.html
---

# Virtual Machine Fingerprinting via Grep [prebuilt-rule-8-17-4-virtual-machine-fingerprinting-via-grep]

An adversary may attempt to get detailed information about the operating system and hardware. This rule identifies common locations used to discover virtual machine hardware by a non-root user. This technique has been used by the Pupy RAT and other malware.

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

* [https://objective-see.com/blog/blog_0x4F.html](https://objective-see.com/blog/blog_0x4F.md)

**Tags**:

* Domain: Endpoint
* OS: macOS
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3963]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Virtual Machine Fingerprinting via Grep**

Virtual machine fingerprinting involves identifying virtualized environments by querying system details. Adversaries exploit tools like `grep` to extract information about virtual machine hardware, aiding in evasion or targeting. The detection rule identifies non-root users executing `grep` with arguments linked to virtual machine identifiers, flagging potential reconnaissance activities while excluding benign processes.

**Possible investigation steps**

* Review the process execution details to confirm the non-root user who initiated the `grep` or `egrep` command and assess their typical behavior and access rights.
* Examine the command-line arguments used with `grep` to identify specific virtual machine identifiers such as "parallels", "vmware", or "virtualbox" and determine if these align with known reconnaissance patterns.
* Investigate the parent process of the `grep` command to understand the context in which it was executed, ensuring it is not a benign process like Docker or kcare.
* Check for any additional suspicious activities or commands executed by the same user around the same time to identify potential lateral movement or further reconnaissance.
* Correlate this event with other security alerts or logs to determine if it is part of a broader attack pattern or campaign, particularly looking for connections to known malware like Pupy RAT.

**False positive analysis**

* Non-root users running legitimate scripts or applications that query virtual machine identifiers for system management or inventory purposes may trigger the rule. To handle this, identify and whitelist these specific scripts or applications by excluding their parent executable paths.
* Developers or IT personnel using grep to troubleshoot or gather system information on virtual machines might be flagged. Create exceptions for known user accounts or specific directories where these activities are expected.
* Automated monitoring tools that check virtual machine environments for compliance or performance metrics could cause false positives. Exclude these tools by adding their process names or parent executables to the exception list.
* Some virtualization management software might use grep internally to gather system information. Identify these applications and exclude their processes to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further reconnaissance or data exfiltration by the adversary.
* Terminate any suspicious processes identified by the alert, specifically those involving `grep` or `egrep` with arguments related to virtual machine identifiers.
* Conduct a thorough review of the affected system’s user accounts and permissions, focusing on non-root users, to identify any unauthorized access or privilege escalation.
* Analyze system logs and network traffic for any signs of lateral movement or additional compromise, paying close attention to connections initiated by the affected system.
* Restore the system from a known good backup if any unauthorized changes or malware are detected, ensuring that the backup is free from compromise.
* Implement stricter access controls and monitoring for systems running virtual machines, including enhanced logging and alerting for similar reconnaissance activities.
* Escalate the incident to the security operations team for further investigation and to determine if the activity is part of a larger attack campaign.


## Setup [_setup_915]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_4980]

```js
process where event.type == "start" and
 process.name in ("grep", "egrep") and user.id != "0" and
 process.args : ("parallels*", "vmware*", "virtualbox*") and process.args : "Manufacturer*" and
 not process.parent.executable in ("/Applications/Docker.app/Contents/MacOS/Docker", "/usr/libexec/kcare/virt-what")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)



