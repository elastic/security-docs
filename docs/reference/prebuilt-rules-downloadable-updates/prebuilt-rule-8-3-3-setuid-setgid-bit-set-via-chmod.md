---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-setuid-setgid-bit-set-via-chmod.html
---

# Setuid / Setgid Bit Set via chmod [prebuilt-rule-8-3-3-setuid-setgid-bit-set-via-chmod]

An adversary may add the setuid or setgid bit to a file or directory in order to run a file with the privileges of the owning user or group. An adversary can take advantage of this to either do a shell escape or exploit a vulnerability in an application with the setuid or setgid bit to get code running in a different user’s context. Additionally, adversaries can use this mechanism on their own malware to make sure they’re able to execute in elevated contexts in the future.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 33

**References**: None

**Tags**:

* Elastic
* Host
* Linux
* macOS
* Threat Detection
* Privilege Escalation

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3298]

```js
event.category:process AND event.type:(start OR process_started) AND
 process.name:chmod AND process.args:("+s" OR "u+s" OR /4[0-9]{3}/ OR g+s OR /2[0-9]{3}/) AND
 NOT process.args:
           (
             /.*\/Applications\/VirtualBox.app\/.+/ OR
             /\/usr\/local\/lib\/python.+/ OR
             /\/var\/folders\/.+\/FP.*nstallHelper/ OR
             /\/Library\/Filesystems\/.+/ OR
             /\/usr\/lib\/virtualbox\/.+/ OR
             /\/Library\/Application.*/ OR
             "/run/postgresql" OR
             "/var/crash" OR
             "/var/run/postgresql" OR
             /\/usr\/bin\/.+/ OR /\/usr\/local\/share\/.+/ OR
             /\/Applications\/.+/ OR /\/usr\/libexec\/.+/ OR
             "/var/metrics" OR /\/var\/lib\/dpkg\/.+/ OR
             /\/run\/log\/journal\/.*/ OR
             \/Users\/*\/.minikube\/bin\/docker-machine-driver-hyperkit
           ) AND
 NOT process.parent.executable:
           (
             /\/var\/lib\/docker\/.+/ OR
             "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/package_script_service.xpc/Contents/MacOS/package_script_service" OR
             "/var/lib/dpkg/info/whoopsie.postinst"
           )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Setuid and Setgid
    * ID: T1548.001
    * Reference URL: [https://attack.mitre.org/techniques/T1548/001/](https://attack.mitre.org/techniques/T1548/001/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)



