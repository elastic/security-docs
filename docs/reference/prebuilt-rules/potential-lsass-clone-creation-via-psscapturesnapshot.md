---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-lsass-clone-creation-via-psscapturesnapshot.html
---

# Potential LSASS Clone Creation via PssCaptureSnapShot [potential-lsass-clone-creation-via-psscapturesnapshot]

Identifies the creation of an LSASS process clone via PssCaptureSnapShot where the parent process is the initial LSASS process instance. This may indicate an attempt to evade detection and dump LSASS memory for credential access.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/](https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/)
* [https://medium.com/@Achilles8284/the-birth-of-a-process-part-2-97c6fb9c42a2](https://medium.com/@Achilles8284/the-birth-of-a-process-part-2-97c6fb9c42a2)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Sysmon
* Data Source: System
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_696]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential LSASS Clone Creation via PssCaptureSnapShot**

PssCaptureSnapShot is a Windows API used for creating snapshots of processes, often for debugging. Adversaries exploit this to clone the LSASS process, aiming to extract credentials without detection. The detection rule identifies suspicious LSASS clones by monitoring process creation events where both the process and its parent are LSASS, signaling potential credential dumping attempts.

**Possible investigation steps**

* Review the process creation event logs for the specific event code 4688 to confirm the creation of an LSASS process clone. Verify that both the process and its parent have the executable path "?:\Windows\System32\lsass.exe".
* Check the timeline of events to determine if there are any preceding or subsequent suspicious activities related to the LSASS process, such as unusual access patterns or modifications.
* Investigate the user account and privileges associated with the process creation event to assess if the account has legitimate reasons to interact with LSASS or if it might be compromised.
* Analyze network activity from the host to identify any potential data exfiltration attempts or connections to known malicious IP addresses following the LSASS clone creation.
* Correlate this event with other security alerts or logs from the same host to identify if this is part of a broader attack pattern or isolated incident.
* Examine the host for any signs of malware or tools commonly used for credential dumping, such as Mimikatz, that might have been used in conjunction with the LSASS clone creation.

**False positive analysis**

* Legitimate security software or system management tools may create LSASS process snapshots for monitoring or debugging purposes. Identify these tools and create exceptions for their process creation events to avoid false positives.
* System administrators or IT personnel might use authorized scripts or tools that interact with LSASS for legitimate reasons. Verify these activities and whitelist the associated processes to prevent unnecessary alerts.
* During system updates or patches, certain processes might temporarily mimic suspicious behavior. Monitor these updates and temporarily adjust detection rules to accommodate expected changes in process behavior.
* Some enterprise environments may have custom applications that interact with LSASS for performance monitoring. Document these applications and exclude their process creation events from triggering alerts.
* Regularly review and update the list of known benign processes and tools that interact with LSASS to ensure that the detection rule remains effective without generating excessive false positives.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further credential access or lateral movement by the adversary.
* Terminate any suspicious LSASS clone processes identified by the detection rule to halt ongoing credential dumping activities.
* Conduct a thorough memory analysis of the affected system to identify any additional malicious activities or tools used by the adversary.
* Change all potentially compromised credentials, especially those with administrative privileges, to mitigate the risk of unauthorized access.
* Review and enhance endpoint security configurations to ensure that LSASS process memory is protected from unauthorized access, such as enabling Credential Guard if applicable.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the scope of the breach.
* Implement additional monitoring and alerting for similar suspicious activities, focusing on process creation events involving LSASS, to improve early detection of future attempts.


## Setup [_setup_443]

**Setup**

This is meant to run only on datasources using Windows security event 4688 that captures the process clone creation.

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_736]

```js
process where host.os.type == "windows" and event.code:"4688" and
  process.executable : "?:\\Windows\\System32\\lsass.exe" and
  process.parent.executable : "?:\\Windows\\System32\\lsass.exe"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: LSASS Memory
    * ID: T1003.001
    * Reference URL: [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)



