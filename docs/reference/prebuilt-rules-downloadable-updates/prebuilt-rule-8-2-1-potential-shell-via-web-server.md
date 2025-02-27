---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-potential-shell-via-web-server.html
---

# Potential Shell via Web Server [prebuilt-rule-8-2-1-potential-shell-via-web-server]

Identifies suspicious commands executed via a web server, which may suggest a vulnerability and remote shell access.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://pentestlab.blog/tag/web-shell/](https://pentestlab.blog/tag/web-shell/)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Persistence

**Version**: 11

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2552]

```js
event.category:process and event.type:(start or process_started) and
process.name:(bash or dash or ash or zsh or "python*" or "perl*" or "php*") and
process.parent.name:("apache" or "nginx" or "www" or "apache2" or "httpd" or "www-data")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Server Software Component
    * ID: T1505
    * Reference URL: [https://attack.mitre.org/techniques/T1505/](https://attack.mitre.org/techniques/T1505/)

* Sub-technique:

    * Name: Web Shell
    * ID: T1505.003
    * Reference URL: [https://attack.mitre.org/techniques/T1505/003/](https://attack.mitre.org/techniques/T1505/003/)



