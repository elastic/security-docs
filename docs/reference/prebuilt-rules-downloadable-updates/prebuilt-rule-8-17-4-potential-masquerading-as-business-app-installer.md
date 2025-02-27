---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-masquerading-as-business-app-installer.html
---

# Potential Masquerading as Business App Installer [prebuilt-rule-8-17-4-potential-masquerading-as-business-app-installer]

Identifies executables with names resembling legitimate business applications but lacking signatures from the original developer. Attackers may trick users into downloading malicious executables that masquerade as legitimate applications via malicious ads, forum posts, and tutorials, effectively gaining initial access.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.rapid7.com/blog/post/2023/08/31/fake-update-utilizes-new-idat-loader-to-execute-stealc-and-lumma-infostealers](https://www.rapid7.com/blog/post/2023/08/31/fake-update-utilizes-new-idat-loader-to-execute-stealc-and-lumma-infostealers)

**Tags**:

* Domain: Endpoint
* Data Source: Elastic Defend
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Initial Access
* Tactic: Execution
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4773]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Masquerading as Business App Installer**

Business applications are integral to productivity, often downloaded and installed by users. Adversaries exploit this by creating malicious executables with names mimicking legitimate apps, tricking users into installing them. The detection rule identifies such threats by checking for unsigned executables in download directories, ensuring they don’t masquerade as trusted applications.

**Possible investigation steps**

* Review the process name and executable path to confirm if it matches any known legitimate business application names listed in the rule, such as Slack, WebEx, or Teams, and verify if it was executed from a typical download directory.
* Check the process code signature status and subject name to determine if the executable is unsigned or signed by an untrusted entity, which could indicate a masquerading attempt.
* Investigate the source of the download by examining browser history, email attachments, or any recent file transfers to identify potential phishing attempts or malicious download sources.
* Analyze the process execution context, including parent processes and command-line arguments, to understand how the executable was launched and if it aligns with typical user behavior.
* Look for any network connections initiated by the process to identify suspicious outbound traffic or connections to known malicious IP addresses or domains.
* Cross-reference the executable’s hash with threat intelligence databases to check for known malware signatures or previous reports of malicious activity.
* If the executable is determined to be suspicious, isolate the affected system and perform a full malware scan to prevent further compromise.

**False positive analysis**

* Unsigned executables from legitimate developers may trigger alerts if they are not properly signed or if the signature is not recognized. Users can create exceptions for specific executables by verifying the developer’s authenticity and adding them to a trusted list.
* Custom or in-house developed applications that mimic business app names but are unsigned can cause false positives. Organizations should ensure these applications are signed with a trusted certificate or add them to an exclusion list after verifying their safety.
* Software updates or beta versions of legitimate applications might not have updated signatures, leading to false positives. Users should verify the source of the update and, if legitimate, temporarily exclude these versions from the rule.
* Applications installed in non-standard directories that match the naming patterns but are legitimate can be excluded by specifying trusted paths or directories in the rule configuration.
* Third-party tools or utilities that integrate with business applications and use similar naming conventions might be flagged. Users should verify these tools and, if safe, add them to an exception list to prevent future alerts.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of the potential threat and to contain any malicious activity.
* Terminate the suspicious process identified by the alert to stop any ongoing malicious actions.
* Quarantine the executable file flagged by the detection rule to prevent execution and further analysis.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or remnants.
* Review and analyze the process execution logs and any related network activity to understand the scope of the intrusion and identify any other potentially compromised systems.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement application whitelisting to prevent unauthorized executables from running, ensuring only trusted and signed applications are allowed to execute.


## Rule query [_rule_query_5728]

```js
process where host.os.type == "windows" and
  event.type == "start" and process.executable : "?:\\Users\\*\\Downloads\\*" and
  not process.code_signature.status : ("errorCode_endpoint*", "errorUntrustedRoot", "errorChaining") and
  (
    /* Slack */
    (process.name : "*slack*.exe" and not
      (process.code_signature.subject_name in (
        "Slack Technologies, Inc.",
        "Slack Technologies, LLC"
       ) and process.code_signature.trusted == true)
    ) or

    /* WebEx */
    (process.name : "*webex*.exe" and not
      (process.code_signature.subject_name in ("Cisco WebEx LLC", "Cisco Systems, Inc.") and process.code_signature.trusted == true)
    ) or

    /* Teams */
    (process.name : "teams*.exe" and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Discord */
    (process.name : "*discord*.exe" and not
      (process.code_signature.subject_name == "Discord Inc." and process.code_signature.trusted == true)
    ) or

    /* WhatsApp */
    (process.name : "*whatsapp*.exe" and not
      (process.code_signature.subject_name in (
        "WhatsApp LLC",
        "WhatsApp, Inc",
        "24803D75-212C-471A-BC57-9EF86AB91435"
       ) and process.code_signature.trusted == true)
    ) or

    /* Zoom */
    (process.name : ("*zoom*installer*.exe", "*zoom*setup*.exe", "zoom.exe")  and not
      (process.code_signature.subject_name == "Zoom Video Communications, Inc." and process.code_signature.trusted == true)
    ) or

    /* Outlook */
    (process.name : "*outlook*.exe" and not
      (
        (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true) or
        (
          process.name: "MSOutlookHelp-PST-Viewer.exe" and process.code_signature.subject_name == "Aryson Technologies Pvt. Ltd" and
          process.code_signature.trusted == true
        )
      )
    ) or

    /* Thunderbird */
    (process.name : "*thunderbird*.exe" and not
      (process.code_signature.subject_name == "Mozilla Corporation" and process.code_signature.trusted == true)
    ) or

    /* Grammarly */
    (process.name : "*grammarly*.exe" and not
      (process.code_signature.subject_name == "Grammarly, Inc." and process.code_signature.trusted == true)
    ) or

    /* Dropbox */
    (process.name : "*dropbox*.exe" and not
      (process.code_signature.subject_name == "Dropbox, Inc" and process.code_signature.trusted == true)
    ) or

    /* Tableau */
    (process.name : "*tableau*.exe" and not
      (process.code_signature.subject_name == "Tableau Software LLC" and process.code_signature.trusted == true)
    ) or

    /* Google Drive */
    (process.name : "*googledrive*.exe" and not
      (process.code_signature.subject_name == "Google LLC" and process.code_signature.trusted == true)
    ) or

    /* MSOffice */
    (process.name : "*office*setup*.exe" and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Okta */
    (process.name : "*okta*.exe" and not
      (process.code_signature.subject_name == "Okta, Inc." and process.code_signature.trusted == true)
    ) or

    /* OneDrive */
    (process.name : "*onedrive*.exe" and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Chrome */
    (process.name : "*chrome*.exe" and not
      (process.code_signature.subject_name in ("Google LLC", "Google Inc") and process.code_signature.trusted == true)
    ) or

    /* Firefox */
    (process.name : "*firefox*.exe" and not
      (process.code_signature.subject_name == "Mozilla Corporation" and process.code_signature.trusted == true)
    ) or

    /* Edge */
    (process.name : ("*microsoftedge*.exe", "*msedge*.exe") and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Brave */
    (process.name : "*brave*.exe" and not
      (process.code_signature.subject_name == "Brave Software, Inc." and process.code_signature.trusted == true)
    ) or

    /* GoogleCloud Related Tools */
    (process.name : "*GoogleCloud*.exe" and not
      (process.code_signature.subject_name == "Google LLC" and process.code_signature.trusted == true)
    ) or

    /* Github Related Tools */
    (process.name : "*github*.exe" and not
      (process.code_signature.subject_name == "GitHub, Inc." and process.code_signature.trusted == true)
    ) or

    /* Notion */
    (process.name : "*notion*.exe" and not
      (process.code_signature.subject_name == "Notion Labs, Inc." and process.code_signature.trusted == true)
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

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Drive-by Compromise
    * ID: T1189
    * Reference URL: [https://attack.mitre.org/techniques/T1189/](https://attack.mitre.org/techniques/T1189/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: User Execution
    * ID: T1204
    * Reference URL: [https://attack.mitre.org/techniques/T1204/](https://attack.mitre.org/techniques/T1204/)

* Sub-technique:

    * Name: Malicious File
    * ID: T1204.002
    * Reference URL: [https://attack.mitre.org/techniques/T1204/002/](https://attack.mitre.org/techniques/T1204/002/)



