---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-web-application-suspicious-activity-sqlmap-user-agent.html
---

# Web Application Suspicious Activity: sqlmap User Agent [prebuilt-rule-8-17-4-web-application-suspicious-activity-sqlmap-user-agent]

This is an example of how to detect an unwanted web client user agent. This search matches the user agent for sqlmap 1.3.11, which is a popular FOSS tool for testing web applications for SQL injection vulnerabilities.

**Rule type**: query

**Rule indices**:

* apm-**-transaction**
* traces-apm*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [http://sqlmap.org/](http://sqlmap.org/)

**Tags**:

* Data Source: APM
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3950]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Web Application Suspicious Activity: sqlmap User Agent**

Sqlmap is a widely-used open-source tool designed to automate the detection and exploitation of SQL injection vulnerabilities in web applications. Adversaries may exploit sqlmap to extract sensitive data or manipulate databases. The detection rule identifies suspicious activity by monitoring for specific user agent strings associated with sqlmap, flagging potential unauthorized testing or attacks on web applications.

**Possible investigation steps**

* Review the logs to identify the source IP address associated with the user agent string "sqlmap/1.3.11#stable ([http://sqlmap.org)"](http://sqlmap.org)") to determine the origin of the suspicious activity.
* Check for any other user agent strings or unusual activity from the same IP address to assess if there are additional signs of probing or attacks.
* Investigate the targeted web application endpoints to understand which parts of the application were accessed and if any SQL injection attempts were successful.
* Correlate the timestamp of the detected activity with other security logs or alerts to identify any concurrent suspicious activities or anomalies.
* Assess the potential impact by reviewing database logs or application logs for any unauthorized data access or modifications during the time of the detected activity.
* Consider blocking or monitoring the identified IP address to prevent further unauthorized access attempts, if deemed malicious.

**False positive analysis**

* Development and testing environments may use sqlmap for legitimate security testing. To handle this, create exceptions for known IP addresses or user agents associated with internal security teams.
* Automated security scanners or vulnerability assessment tools might mimic sqlmap’s user agent for testing purposes. Identify and whitelist these tools to prevent unnecessary alerts.
* Some web application firewalls or intrusion detection systems may simulate sqlmap activity to test their own detection capabilities. Coordinate with your security infrastructure team to recognize and exclude these activities.
* Educational institutions or training environments might use sqlmap for teaching purposes. Establish a list of authorized users or networks to exclude from alerts.
* Ensure that any third-party security service providers are recognized and their activities are documented to avoid misidentification as threats.

**Response and remediation**

* Immediately block the IP address associated with the sqlmap user agent activity to prevent further unauthorized access attempts.
* Review and analyze web server logs to identify any additional suspicious activity or patterns that may indicate further exploitation attempts.
* Conduct a thorough assessment of the affected web application to identify and patch any SQL injection vulnerabilities that may have been exploited.
* Reset credentials and enforce strong password policies for any database accounts that may have been compromised.
* Implement web application firewall (WAF) rules to detect and block SQL injection attempts, including those using sqlmap.
* Notify the security operations team and relevant stakeholders about the incident for awareness and further investigation.
* Document the incident details and response actions taken for future reference and to enhance incident response procedures.


## Rule query [_rule_query_4967]

```js
user_agent.original:"sqlmap/1.3.11#stable (http://sqlmap.org)"
```


