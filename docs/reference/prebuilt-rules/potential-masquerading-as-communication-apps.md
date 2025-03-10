---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-masquerading-as-communication-apps.html
---

# Potential Masquerading as Communication Apps [potential-masquerading-as-communication-apps]

Identifies suspicious instances of communications apps, both unsigned and renamed ones, that can indicate an attempt to conceal malicious activity, bypass security features such as allowlists, or trick users into executing malware.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*

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
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_708]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Masquerading as Communication Apps**

Communication apps are integral to modern workflows, facilitating seamless interaction. However, adversaries can exploit these apps by masquerading malicious processes as legitimate ones, bypassing security measures and deceiving users. The detection rule identifies suspicious instances by checking for unsigned or improperly signed processes, ensuring they match known trusted signatures. This helps in flagging potential threats that mimic trusted communication tools, aiding in defense evasion detection.

**Possible investigation steps**

* Review the process name and code signature details to confirm if the process is indeed masquerading as a legitimate communication app. Check if the process name matches any of the specified apps like slack.exe, WebexHost.exe, etc., and verify the code signature subject name and trust status.
* Investigate the origin of the executable file by checking its file path and creation date. Determine if it was recently added or modified, which might indicate suspicious activity.
* Analyze the parent process to understand how the suspicious process was initiated. This can provide insights into whether it was launched by a legitimate application or a potentially malicious script or program.
* Check for any network connections initiated by the suspicious process. Look for unusual or unauthorized external connections that might suggest data exfiltration or command and control communication.
* Review recent system logs and security alerts for any related activities or anomalies that coincide with the start of the suspicious process. This can help identify if the process is part of a larger attack pattern.
* Consult threat intelligence sources to see if there are any known indicators of compromise (IOCs) associated with the process or its hash value, which can help in assessing the threat level.

**False positive analysis**

* Legitimate software updates or installations may temporarily result in unsigned or improperly signed processes. Users can create exceptions for known update processes to prevent false positives during these periods.
* Custom or internally developed communication tools that mimic the names of popular apps might trigger alerts. Ensure these tools are properly signed and add them to an allowlist if they are trusted.
* Some third-party security or monitoring tools may interact with communication apps in a way that alters their signature status. Verify the legitimacy of these tools and consider excluding them from the rule if they are deemed safe.
* In environments where communication apps are deployed via non-standard methods, such as portable versions, ensure these versions are signed correctly or add them to an exception list if they are verified as safe.
* Temporary network issues or system misconfigurations might cause legitimate apps to appear unsigned. Regularly audit and correct any network or system issues to minimize these occurrences.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further spread of potential malware or unauthorized access.
* Terminate any suspicious processes identified by the detection rule that are masquerading as communication apps, ensuring they are not legitimate processes.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any malicious files or software.
* Review and validate the code signatures of all communication apps on the affected system to ensure they are properly signed by trusted entities.
* Restore any compromised systems from a known good backup to ensure the integrity of the system and data.
* Monitor network traffic and system logs for any signs of lateral movement or further attempts to exploit communication apps.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Rule query [_rule_query_749]

```js
process where host.os.type == "windows" and
  event.type == "start" and
  (
    /* Slack */
    (process.name : "slack.exe" and not
      (process.code_signature.subject_name in (
        "Slack Technologies, Inc.",
        "Slack Technologies, LLC"
       ) and process.code_signature.trusted == true)
    ) or

    /* WebEx */
    (process.name : "WebexHost.exe" and not
      (process.code_signature.subject_name in ("Cisco WebEx LLC", "Cisco Systems, Inc.") and process.code_signature.trusted == true)
    ) or

    /* Teams */
    (process.name : "Teams.exe" and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Discord */
    (process.name : "Discord.exe" and not
      (process.code_signature.subject_name == "Discord Inc." and process.code_signature.trusted == true)
    ) or

    /* RocketChat */
    (process.name : "Rocket.Chat.exe" and not
      (process.code_signature.subject_name == "Rocket.Chat Technologies Corp." and process.code_signature.trusted == true)
    ) or

    /* Mattermost */
    (process.name : "Mattermost.exe" and not
      (process.code_signature.subject_name == "Mattermost, Inc." and process.code_signature.trusted == true)
    ) or

    /* WhatsApp */
    (process.name : "WhatsApp.exe" and not
      (process.code_signature.subject_name in (
        "WhatsApp LLC",
        "WhatsApp, Inc",
        "24803D75-212C-471A-BC57-9EF86AB91435"
       ) and process.code_signature.trusted == true)
    ) or

    /* Zoom */
    (process.name : "Zoom.exe" and not
      (process.code_signature.subject_name == "Zoom Video Communications, Inc." and process.code_signature.trusted == true)
    ) or

    /* Outlook */
    (process.name : "outlook.exe" and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Thunderbird */
    (process.name : "thunderbird.exe" and not
      (process.code_signature.subject_name == "Mozilla Corporation" and process.code_signature.trusted == true)
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Invalid Code Signature
    * ID: T1036.001
    * Reference URL: [https://attack.mitre.org/techniques/T1036/001/](https://attack.mitre.org/techniques/T1036/001/)

* Sub-technique:

    * Name: Match Legitimate Name or Location
    * ID: T1036.005
    * Reference URL: [https://attack.mitre.org/techniques/T1036/005/](https://attack.mitre.org/techniques/T1036/005/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Compromise Host Software Binary
    * ID: T1554
    * Reference URL: [https://attack.mitre.org/techniques/T1554/](https://attack.mitre.org/techniques/T1554/)



