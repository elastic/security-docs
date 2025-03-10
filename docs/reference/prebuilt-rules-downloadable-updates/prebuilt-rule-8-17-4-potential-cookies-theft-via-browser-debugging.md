---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-cookies-theft-via-browser-debugging.html
---

# Potential Cookies Theft via Browser Debugging [prebuilt-rule-8-17-4-potential-cookies-theft-via-browser-debugging]

Identifies the execution of a Chromium based browser with the debugging process argument, which may indicate an attempt to steal authentication cookies. An adversary may steal web application or service session cookies and use them to gain access web applications or Internet services as an authenticated user without needing credentials.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 33

**References**:

* [https://github.com/defaultnamehere/cookie_crimes](https://github.com/defaultnamehere/cookie_crimes)
* [https://embracethered.com/blog/posts/2020/cookie-crimes-on-mirosoft-edge/](https://embracethered.com/blog/posts/2020/cookie-crimes-on-mirosoft-edge/)
* [https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/gather/chrome_cookies.md](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/gather/chrome_cookies.md)
* [https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: Windows
* OS: macOS
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3953]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Cookies Theft via Browser Debugging**

Chromium-based browsers support debugging features that allow developers to inspect and modify web applications. Adversaries can exploit these features to access session cookies, enabling unauthorized access to web services. The detection rule identifies suspicious browser processes using debugging arguments, which may indicate cookie theft attempts, by monitoring specific process names and arguments across different operating systems.

**Possible investigation steps**

* Review the process details to confirm the presence of suspicious debugging arguments such as "--remote-debugging-port=**", "--remote-debugging-targets=**", or "--remote-debugging-pipe=**". Check if these arguments were used in conjunction with "--user-data-dir=**" and ensure "--remote-debugging-port=0" is not present.
* Identify the user account associated with the suspicious browser process to determine if it aligns with expected behavior or if it might be compromised.
* Investigate the source IP address and network activity associated with the process to identify any unusual or unauthorized access patterns.
* Check for any recent changes or anomalies in the user’s account activity, such as unexpected logins or access to sensitive applications.
* Correlate the event with other security alerts or logs to identify if this activity is part of a broader attack pattern or campaign.
* If possible, capture and analyze the network traffic associated with the process to detect any data exfiltration attempts or communication with known malicious IP addresses.

**False positive analysis**

* Development and testing activities may trigger the rule when developers use debugging features for legitimate purposes. To manage this, create exceptions for known developer machines or user accounts frequently involved in web application development.
* Automated testing frameworks that utilize browser debugging for testing web applications can also cause false positives. Identify and exclude processes initiated by these frameworks by specifying their unique process names or user accounts.
* Browser extensions or tools that rely on debugging ports for functionality might be flagged. Review and whitelist these extensions or tools if they are verified as safe and necessary for business operations.
* Remote support or troubleshooting sessions using debugging features can be mistaken for suspicious activity. Implement a policy to log and review such sessions, allowing exceptions for recognized support tools or personnel.
* Continuous integration/continuous deployment (CI/CD) pipelines that involve browser automation may inadvertently match the rule criteria. Exclude these processes by identifying and filtering based on the CI/CD system’s user accounts or process identifiers.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious browser processes identified with debugging arguments to stop potential cookie theft in progress.
* Conduct a thorough review of access logs for the affected web applications or services to identify any unauthorized access attempts using stolen cookies.
* Invalidate all active sessions for the affected user accounts and force a re-authentication to ensure that any stolen session cookies are rendered useless.
* Implement stricter browser security policies, such as disabling remote debugging features in production environments, to prevent similar exploitation in the future.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or data have been compromised.
* Enhance monitoring and alerting for similar suspicious browser activities by refining detection rules and incorporating additional threat intelligence.


## Setup [_setup_908]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_4970]

```js
process where event.type in ("start", "process_started", "info") and
  process.name in (
             "Microsoft Edge",
             "chrome.exe",
             "Google Chrome",
             "google-chrome-stable",
             "google-chrome-beta",
             "google-chrome",
             "msedge.exe") and
   process.args : ("--remote-debugging-port=*",
                   "--remote-debugging-targets=*",
                   "--remote-debugging-pipe=*") and
   process.args : "--user-data-dir=*" and not process.args:"--remote-debugging-port=0"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal Web Session Cookie
    * ID: T1539
    * Reference URL: [https://attack.mitre.org/techniques/T1539/](https://attack.mitre.org/techniques/T1539/)



