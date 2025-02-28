---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/google-workspace-drive-encryption-key-s-accessed-from-anonymous-user.html
---

# Google Workspace Drive Encryption Key(s) Accessed from Anonymous User [google-workspace-drive-encryption-key-s-accessed-from-anonymous-user]

Detects when an external (anonymous) user has viewed, copied or downloaded an encryption key file from a Google Workspace drive. Adversaries may gain access to encryption keys stored in private drives from rogue access links that do not have an expiration. Access to encryption keys may allow adversaries to access sensitive data or authenticate on behalf of users.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-google_workspace*

**Severity**: high

**Risk score**: 73

**Runs every**: 10m

**Searches indices from**: now-130m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://support.google.com/drive/answer/2494822](https://support.google.com/drive/answer/2494822)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)

**Tags**:

* Domain: Cloud
* Data Source: Google Workspace
* Use Case: Configuration Audit
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_395]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Google Workspace Drive Encryption Key(s) Accessed from Anonymous User**

Google Workspace Drive allows users to store and share files, including sensitive encryption keys. If shared improperly, these keys can be accessed by unauthorized users, potentially leading to data breaches. Adversaries exploit links with open access to obtain these keys. The detection rule identifies suspicious activities, such as anonymous access to key files, by monitoring file actions and link visibility settings.

**Possible investigation steps**

* Review the file activity logs to identify the specific file(s) accessed by the anonymous user, focusing on actions such as "copy", "view", or "download" and the file extensions listed in the query.
* Check the sharing settings of the accessed file(s) to confirm if they are set to "people_with_link" and assess whether this level of access is appropriate for the file’s sensitivity.
* Investigate the source of the rogue access link by examining any recent changes to the file’s sharing settings or any unusual activity in the file’s access history.
* Identify and contact the file owner or relevant stakeholders to verify if the sharing of the file was intentional and authorized.
* Assess the potential impact of the accessed encryption key(s) by determining what systems or data they protect and evaluate the risk of unauthorized access.
* Consider revoking or changing the encryption keys if unauthorized access is confirmed to mitigate potential security risks.

**False positive analysis**

* Shared project files with encryption keys may trigger alerts if accessed by external collaborators. To manage this, ensure that only trusted collaborators have access and consider using Google Workspace’s sharing settings to restrict access to specific users.
* Automated backup systems that access encryption keys for legitimate purposes might be flagged. Verify the source of access and, if legitimate, create an exception for the backup system’s IP address or service account.
* Internal users accessing encryption keys via shared links for routine tasks could be misidentified as anonymous users. Encourage users to access files through authenticated sessions and adjust monitoring rules to recognize internal IP ranges or user accounts.
* Third-party integrations that require access to encryption keys might cause false positives. Review the integration’s access patterns and whitelist known, secure integrations to prevent unnecessary alerts.
* Temporary access links for external audits or compliance checks can be mistaken for unauthorized access. Use time-bound access links and document these activities to differentiate them from potential threats.

**Response and remediation**

* Immediately revoke access to the specific Google Workspace Drive file by changing its sharing settings to restrict access to only authorized users.
* Conduct a thorough review of the file’s access history to identify any unauthorized access and determine the scope of potential data exposure.
* Notify the security team and relevant stakeholders about the incident, providing details of the unauthorized access and any potential data compromise.
* Rotate and replace any encryption keys that were accessed or potentially compromised to prevent unauthorized use.
* Implement additional monitoring and alerting for similar file types and sharing settings to detect future unauthorized access attempts.
* Escalate the incident to senior management and, if necessary, involve legal or compliance teams to assess any regulatory implications.
* Review and update access policies and sharing settings within Google Workspace to ensure that sensitive files are not shared with open access links.

**Important Information Regarding Google Workspace Event Lag Times**

* As per Google’s documentation, Google Workspace administrators may observe lag times ranging from minutes up to 3 days between the time of an event’s occurrence and the event being visible in the Google Workspace admin/audit logs.
* This rule is configured to run every 10 minutes with a lookback time of 130 minutes.
* To reduce the risk of false negatives, consider reducing the interval that the Google Workspace (formerly G Suite) Filebeat module polls Google’s reporting API for new events.
* By default, `var.interval` is set to 2 hours (2h). Consider changing this interval to a lower value, such as 10 minutes (10m).
* See the following references for further information:
* [https://support.google.com/a/answer/7061566](https://support.google.com/a/answer/7061566)
* [/beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-google_workspace.md](beats://reference/filebeat/filebeat-module-google_workspace.md)


## Setup [_setup_254]

The Google Workspace Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_430]

```js
file where event.dataset == "google_workspace.drive" and event.action : ("copy", "view", "download") and
    google_workspace.drive.visibility: "people_with_link" and source.user.email == "" and
    file.extension: (
        "token","assig", "pssc", "keystore", "pub", "pgp.asc", "ps1xml", "pem", "gpg.sig", "der", "key",
        "p7r", "p12", "asc", "jks", "p7b", "signature", "gpg", "pgp.sig", "sst", "pgp", "gpgz", "pfx", "crt",
        "p8", "sig", "pkcs7", "jceks", "pkcs8", "psc1", "p7c", "csr", "cer", "spc", "ps2xml")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Unsecured Credentials
    * ID: T1552
    * Reference URL: [https://attack.mitre.org/techniques/T1552/](https://attack.mitre.org/techniques/T1552/)

* Sub-technique:

    * Name: Private Keys
    * ID: T1552.004
    * Reference URL: [https://attack.mitre.org/techniques/T1552/004/](https://attack.mitre.org/techniques/T1552/004/)



