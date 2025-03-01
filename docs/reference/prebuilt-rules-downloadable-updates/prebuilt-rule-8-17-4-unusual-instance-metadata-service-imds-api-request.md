---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-instance-metadata-service-imds-api-request.html
---

# Unusual Instance Metadata Service (IMDS) API Request [prebuilt-rule-8-17-4-unusual-instance-metadata-service-imds-api-request]

This rule identifies potentially malicious processes attempting to access the cloud service provider’s instance metadata service (IMDS) API endpoint, which can be used to retrieve sensitive instance-specific information such as instance ID, public IP address, and even temporary security credentials if role’s are assumed by that instance. The rule monitors for various tools and scripts like curl, wget, python, and perl that might be used to interact with the metadata API.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://hackingthe.cloud/aws/general-knowledge/intro_metadata_service/](https://hackingthe.cloud/aws/general-knowledge/intro_metadata_service/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic: Discovery
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4326]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Instance Metadata Service (IMDS) API Request**

The Instance Metadata Service (IMDS) API provides essential instance-specific data, including configuration details and temporary credentials, to applications running on cloud instances. Adversaries exploit this by using scripts or tools to access sensitive data, potentially leading to unauthorized access. The detection rule identifies suspicious access attempts by monitoring specific processes and network activities, excluding known legitimate paths, to flag potential misuse.

**Possible investigation steps**

* Review the process details such as process.name and process.command_line to identify the tool or script used to access the IMDS API and determine if it aligns with known malicious behavior.
* Examine the process.executable and process.working_directory fields to verify if the execution path is unusual or suspicious, especially if it originates from directories like /tmp/* or /var/tmp/*.
* Check the process.parent.entity_id and process.parent.executable to understand the parent process and its legitimacy, which might provide context on how the suspicious process was initiated.
* Investigate the network event details, particularly the destination.ip field, to confirm if there was an attempted connection to the IMDS API endpoint at 169.254.169.254.
* Correlate the host.id with other security events or logs to identify any additional suspicious activities or patterns on the same host that might indicate a broader compromise.
* Assess the risk score and severity to prioritize the investigation and determine if immediate action is required to mitigate potential threats.

**False positive analysis**

* Security and monitoring tools like Rapid7, Nessus, and Amazon SSM Agent may trigger false positives due to their legitimate access to the IMDS API. Users can exclude these by adding their working directories to the exception list.
* Automated scripts or processes running from known directories such as /opt/rumble/bin or /usr/share/ec2-instance-connect may also cause false positives. Exclude these directories or specific executables from the rule to prevent unnecessary alerts.
* System maintenance or configuration scripts that access the IMDS API for legitimate purposes might be flagged. Identify these scripts and add their paths or parent executables to the exclusion list to reduce noise.
* Regular network monitoring tools that attempt connections to the IMDS IP address for health checks or status updates can be excluded by specifying their process names or executable paths in the exception criteria.

**Response and remediation**

* Immediately isolate the affected instance from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified in the alert that are attempting to access the IMDS API, especially those using tools like curl, wget, or python.
* Revoke any temporary credentials that may have been exposed or accessed through the IMDS API to prevent unauthorized use.
* Conduct a thorough review of the instance’s security groups and IAM roles to ensure that only necessary permissions are granted and that there are no overly permissive policies.
* Escalate the incident to the security operations team for further investigation and to determine if additional instances or resources are affected.
* Implement network monitoring to detect and alert on any future attempts to access the IMDS API from unauthorized processes or locations.
* Review and update the instance’s security configurations and apply any necessary patches or updates to mitigate vulnerabilities that could be exploited in similar attacks.


## Rule query [_rule_query_5318]

```js
sequence by host.id,  process.parent.entity_id with maxspan=1s
[process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
 process.parent.executable != null and
 (
  process.name : (
    "curl", "wget", "python*", "perl*", "php*", "ruby*", "lua*", "telnet", "pwsh",
    "openssl", "nc", "ncat", "netcat", "awk", "gawk", "mawk", "nawk", "socat", "node"
    ) or
  process.executable : (
      "./*", "/tmp/*", "/var/tmp/*", "/var/www/*", "/dev/shm/*", "/etc/init.d/*", "/etc/rc*.d/*",
      "/etc/cron*", "/etc/update-motd.d/*", "/boot/*", "/srv/*", "/run/*", "/etc/rc.local"
    ) or
  process.command_line: "*169.254.169.254*"
  )
  and not process.working_directory: (
          "/opt/rapid7*",
          "/opt/nessus*",
          "/snap/amazon-ssm-agent*",
          "/var/snap/amazon-ssm-agent/*",
          "/var/log/amazon/ssm/*",
          "/srv/snp/docker/overlay2*",
          "/opt/nessus_agent/var/nessus/*")
  and not process.executable: (
          "/opt/rumble/bin/rumble-agent*",
          "/opt/aws/inspector/bin/inspectorssmplugin",
          "/snap/oracle-cloud-agent/*",
          "/lusr/libexec/oracle-cloud-agent/*")
  and not process.parent.executable: (
          "/usr/bin/setup-policy-routes",
          "/usr/share/ec2-instance-connect/*",
          "/var/lib/amazon/ssm/*",
          "/etc/update-motd.d/30-banner",
          "/usr/sbin/dhclient-script",
          "/usr/local/bin/uwsgi",
          "/usr/lib/skylight/al-extras")
]
[network where host.os.type == "linux" and event.action == "connection_attempted" and destination.ip == "169.254.169.254"]
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

    * Name: Cloud Instance Metadata API
    * ID: T1552.005
    * Reference URL: [https://attack.mitre.org/techniques/T1552/005/](https://attack.mitre.org/techniques/T1552/005/)

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Cloud Infrastructure Discovery
    * ID: T1580
    * Reference URL: [https://attack.mitre.org/techniques/T1580/](https://attack.mitre.org/techniques/T1580/)



