---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-file-downloaded-from-google-drive.html
---

# Suspicious File Downloaded from Google Drive [suspicious-file-downloaded-from-google-drive]

Identifies suspicious file download activity from a Google Drive URL. This could indicate an attempt to deliver phishing payloads via a trusted webservice.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint*
* logs-system.security*
* winlogbeat-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://intelligence.abnormalsecurity.com/blog/google-drive-matanbuchus-malware](https://intelligence.abnormalsecurity.com/blog/google-drive-matanbuchus-malware)

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: Windows
* OS: macOS
* Use Case: Threat Detection
* Tactic: Command and Control
* Data Source: System
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_990]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious File Downloaded from Google Drive**

Google Drive is a widely-used cloud storage service that allows users to store and share files. Adversaries may exploit its trusted nature to distribute malicious files, bypassing security measures by using download links with antivirus checks disabled. The detection rule identifies such activities by monitoring browser processes for specific Google Drive download patterns, flagging potential threats for further investigation.

**Possible investigation steps**

* Review the process command line details to confirm the presence of the Google Drive download URL with the "export=download" and "confirm=no_antivirus" parameters, which indicate an attempt to bypass antivirus checks.
* Identify the user account associated with the process to determine if the activity aligns with their typical behavior or if it appears suspicious.
* Check the file downloaded from the Google Drive URL for any known malicious signatures or behaviors using a reputable antivirus or malware analysis tool.
* Investigate the source of the download link to determine if it was shared via email, messaging, or another communication channel, and assess the legitimacy of the source.
* Analyze network logs to identify any additional suspicious activity or connections related to the IP address or domain associated with the download.
* Review historical data for any previous similar alerts or activities involving the same user or device to identify potential patterns or repeated attempts.

**False positive analysis**

* Legitimate file sharing activities from Google Drive may trigger alerts if users frequently download files for business purposes. To manage this, create exceptions for specific users or departments known to use Google Drive extensively for legitimate work.
* Automated scripts or tools that download files from Google Drive for regular data processing tasks might be flagged. Identify these scripts and whitelist their associated processes or command lines to prevent unnecessary alerts.
* Educational institutions or research organizations often share large datasets via Google Drive, which could be mistakenly flagged. Implement exceptions for known educational or research-related Google Drive URLs to reduce false positives.
* Internal IT or security teams may use Google Drive to distribute software updates or patches. Recognize these activities and exclude them by specifying trusted internal Google Drive links or user accounts.
* Collaboration with external partners who use Google Drive for file sharing can lead to false positives. Establish a list of trusted partners and their associated Google Drive URLs to minimize unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further spread of potential malware or unauthorized access.
* Quarantine the downloaded file and perform a detailed malware analysis using a sandbox environment to determine its behavior and potential impact.
* If malware is confirmed, initiate a full system scan using updated antivirus and anti-malware tools to identify and remove any additional threats.
* Review and analyze the process command line logs to identify any other suspicious activities or downloads that may have occurred concurrently.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.
* Implement network-level blocking of the specific Google Drive URL or domain if it is confirmed to be malicious, to prevent future access.
* Update endpoint detection and response (EDR) systems with indicators of compromise (IOCs) identified during the analysis to enhance detection of similar threats in the future.


## Rule query [_rule_query_1039]

```js
process where

    /* common browser processes  */
    event.action in ("exec", "fork", "start") and

    process.name : ("Microsoft Edge", "chrome.exe", "Google Chrome", "google-chrome-stable",
                    "google-chrome-beta", "google-chrome", "msedge.exe", "firefox.exe", "brave.exe",
                    "whale.exe", "browser.exe", "dragon.exe", "vivaldi.exe", "opera.exe", "firefox",
                    "powershell.exe", "curl", "curl.exe", "wget", "wget.exe") and

    /* Look for Google Drive download URL with AV flag skipping */
    (process.command_line : "*drive.google.com*" and process.command_line : "*export=download*" and process.command_line : "*confirm=no_antivirus*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Ingress Tool Transfer
    * ID: T1105
    * Reference URL: [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)



