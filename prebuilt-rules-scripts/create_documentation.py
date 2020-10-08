import json
import textwrap
import toml
import os
import glob
from pathlib import Path
import re

# Creates the asciidoc files for the documentation. All prebuilt rule doc files
# are generated, even those that have not been changed, so you can just copy and
# paste the updated files to the documentation folders.

def sort_by_name(rule):
    '''
    Helper to sort rule by name'''
    return rule['name']
    
def sort_tag_by_name(tag):
    '''
    Helper to sort tags by name'''
    return rule['tag']
    
def translate_interval_period(interval):
    units = ""
    length = ""
    runtime = re.match(r"([0-9]+)([a-z]+)", interval, re.I)
    if runtime:
        runtime = runtime.groups()
    if len(runtime) == 2:  
        if runtime[1] == 'm':
            units = "minutes"
        elif runtime[1] == 's':
            units = "seconds"
        elif runtime[1] == 'h':
            units = "hours"
        elif runtime[1] == 'H':
            units = "hours"
        elif runtime[1] == 'd':
            units = "days"
        elif runtime[1] == 'w':
            units = "weeks"
        elif runtime[1] == 'M':
            units = "months"
        elif runtime[1] == 'y':
            units = "years"
        else:
            units = ""
        length = runtime[0]
        if length == "1":
            units = units[:-1]
    return str(length + " " + units)

# Formats text using asciidoc syntax

def formatText(text):
    return text.replace('\\n', '\n')

# Path to the generated JSON file

with open('diff-files/final-files/final-rule-file-7.9.0.json', 'r') as source:
     rules_dict = json.load(source)


sorted_rules = sorted(rules_dict, key=sort_by_name)

newText = """[[prebuilt-rules]]
[role="xpack"]
== Prebuilt rule reference

beta[]

This section lists all available prebuilt rules.

IMPORTANT: To run {ml} prebuilt rules, you must have the
https://www.elastic.co/subscriptions[appropriate license] or use a
{ess-trial}[Cloud] deployment. All {ml} prebuilt rules are tagged with `ML`,
and their rule type is `machine_learning`.

[width="100%",options="header"]
|==============================================
|Rule |Description |Tags |Added |Version


"""

# Creates overview table


for rule in sorted_rules:
    tagStrings = ""
    versionText = ""
    linkString = re.sub(' ', '-', rule['name'].lower())
    linkString = re.sub('[():]', '', linkString)
    linkString = re.sub('-+', '-', linkString)
    linkString = re.sub('/', '-', linkString)
    newText = newText + "|<<" + linkString + ", " + rule['name'] + ">> |" + re.sub(' +', ' ', rule['description'].replace('\n', ' '))
    for i in rule['tags']:
        tagStrings = tagStrings + "[" + i  + "] "
    if rule['version'] == 1:
        versionText = str(rule['version'])
    if rule['version'] > 1:
        versionText = str(rule['version']) + " <<" + linkString + "-history, Version history>>"
    newText = newText + " |" + tagStrings + " |" + rule['added'] + " |" + versionText + "\n\n"
    tagStrings = ""

newText = newText + "|=============================================="

fileWrite = "generated-ascii-files" + "/" + "prebuilt-rules-reference.asciidoc"
with open(fileWrite, "w") as writeFile:
        writeFile.write(newText)
    
        
# End overview table

# Create files for each rule and the index (ToC) file

fileText = ""
rules_index_file = []

for rule in sorted_rules:
    rule_link = re.sub(' ', '-', rule['name'].lower())
    rule_link = re.sub('[():]', '', rule_link)
    rule_link = re.sub('-+', '-', rule_link)
    rule_link = re.sub('/', '-', rule_link)
    fileText = "[[" + rule_link + "]]\n=== " + rule['name'] + "\n\n"
    fileText = fileText + formatText(rule['description']) + "\n\n"
    fileText = fileText + "*Rule type*: " + rule['type'] + "\n\n"
    if 'machine_learning_job_id' in rule:
        fileText = fileText + "*Machine learning job*: " + rule['machine_learning_job_id'] + "\n\n"
        fileText = fileText + "*Machine learning anomaly threshold*: " + str(rule['anomaly_threshold']) + "\n\n"
    if 'index' in rule:
        if len(rule['index']) != 0:
            fileText = fileText + "*Rule indices*:" + "\n\n"
            for i in rule['index']:
                fileText = fileText + "* " + i + "\n"
        else:
            fileText = fileText + "*Rule index*: " + rule['index'] + "\n\n"
    fileText = fileText + "\n*Severity*: " + rule['severity'] + "\n\n"
    fileText = fileText + "*Risk score*: " + str(rule['risk_score']) + "\n\n"
    fileText = fileText + "*Runs every*: " + translate_interval_period(rule['interval']) + "\n\n"
    fileText = fileText + "*Searches indices from*: " + rule['from'] + " ({ref}/common-options.html#date-math[Date Math format], see also <<rule-schedule, `Additional look-back time`>>)" + "\n\n"
    fileText = fileText + "*Maximum alerts per execution*: " + str(rule['max_signals']) + "\n\n"
    if len(rule['references']) != 0:
        fileText = fileText + "*References*:\n\n"
        for i in rule['references']:
            fileText = fileText + "* " + i + "\n"
    if len(rule['references']) != 0:
        fileText = fileText + "\n"
    fileText = fileText + "*Tags*:\n\n"
    for i in rule['tags']:
        fileText = fileText + "* " + i + "\n"
    if rule['version'] == 1:
        fileText = fileText + "\n*Version*: " + str(rule['version']) + "\n\n"
    if rule['version'] > 1:
        fileText = fileText + "\n*Version*: " + str(rule['version']) + " (<<" + rule_link + "-history, version history>>)" + "\n\n"
    fileText = fileText + "*Added ({stack} release)*: " + rule['added'] + "\n\n"
    if rule['version'] > 1:
        fileText = fileText + "*Last modified ({stack} release)*: " + rule['last_update'] + "\n\n"
    fileText = fileText + "*Rule authors*: "
    for count, i in enumerate(rule['author']):
        if count > 0:
            fileText = fileText + ", "
        fileText = fileText + i
    fileText = fileText + "\n\n"
    fileText = fileText + "*Rule license*: " + rule['license'] + "\n"
    if len(rule['false_positives']) != 0:
        fileText = fileText + "\n==== Potential false positives" + "\n\n"
        for i in rule['false_positives']:
            fileText = fileText + formatText(i) + "\n"
    if 'note' in rule:
        fileText = fileText + "\n==== Investigation guide" + "\n\n"
        fileText = fileText + formatText(rule['note']) + "\n"
    if 'query' in rule:
        fileText = fileText + "\n==== Rule query\n\n"
        fileText = fileText + "\n[source,js]\n"
        fileText = fileText + "----------------------------------" + "\n"
        fileText = fileText + re.sub(' +', ' ', textwrap.fill(rule['query'], width=70)) + "\n"
        fileText = fileText + "----------------------------------" + "\n\n"
    if 'filters' in rule:
        if len(rule['filters']) != 0:
            fileText = fileText + "==== Rule filters" + "\n\n"
            fileText = fileText + "[source,js]\n"
            fileText = fileText + "----------------------------------" + "\n"
            for i in rule['filters']:
                fileText = fileText + json.dumps(i, sort_keys=True, indent=4) + "\n"
            fileText = fileText + "----------------------------------" + "\n\n"
    if len(rule['threat']) != 0:
        fileText = fileText + "==== Threat mapping" + "\n\n"
        isFirstLoop = True
        for i in rule['threat']:
            if isFirstLoop:
                fileText = fileText + "*Framework*: " + i['framework']
                isFirstLoop = False
                if i['framework'] == "MITRE ATT&CK":
                    fileText = fileText + "^TM^"
            fileText = fileText + "\n\n* Tactic:\n"
            fileText = fileText + "** Name: " + i['tactic']['name'] + "\n"
            fileText = fileText + "** ID: " + i['tactic']['id'] + "\n"
            fileText = fileText + "** Reference URL: " + i['tactic']['reference'] + "\n"
            fileText = fileText + "* Technique:\n"
            fileText = fileText + "** Name: " + i['technique'][0]['name'] + "\n"
            fileText = fileText + "** ID: " + i['technique'][0]['id'] + "\n"
            fileText = fileText + "** Reference URL: " + i['technique'][0]['reference'] + "\n"
    if 'changelog' in rule:
        identifier = rule_link + "-history"
        fileText = fileText + "\n[[" + identifier + "]]\n"
        fileText = fileText + "==== Rule version history" + "\n\n"
        for i in reversed(rule['changelog']['changes']):
            fileText = fileText + "Version " + str(i['version']) + " (" + i['updated'] + " release)" + "::\n"
            if i['doc_text'] == "Updated query.":
                fileText = fileText + "Updated query, changed from:\n+\n"
                fileText = fileText + "[source, js]\n"
                fileText = fileText + "----------------------------------" + "\n"
                fileText = fileText + re.sub(' +', ' ', textwrap.fill(i['pre_query'], width=70)) + "\n"
                fileText = fileText + "----------------------------------" + "\n\n"
            else:
                fileText = fileText + "* " + i['doc_text'] + "\n"
    asciidocFile = "generated-ascii-files/rule-details/" + rule_link + ".asciidoc"
    with open(asciidocFile, "w") as asciiWrite:
        asciiWrite.write(fileText)
    rules_index_file.append("include::rule-details/" + rule_link + ".asciidoc[]")
    print("include::rule-details/" + rule_link + ".asciidoc[]")
    print()

# Create index file

index_file_text = ""

for index_link in rules_index_file:
    index_file_text += index_link + "\n"

indexFileWrite = "generated-ascii-files" + "/" + "rule-desc-index.asciidoc"
with open(indexFileWrite, "w") as indexFileWrite:
        indexFileWrite.write(index_file_text)

# END: Create files for each rule

# START: Create rule changelog file. This needs updating each release to add
# rules changed for the new release.

versionHistoryPage = """[[prebuilt-rules-changelog]]
== Prebuilt rule changes per release

beta[]

The following lists prebuilt rule updates per release. Only rules with
significant modifications to their query or scope are listed. For detailed
information about a rule's changes, see the rule's description page.

"""

def addVersionUpdates(updated):
    global versionHistoryPage
    versionHistoryPage = versionHistoryPage + "[float]\n"
    versionHistoryPage = versionHistoryPage + "=== " + updated + "\n\n"
    for rule in sorted_rules:
        if 'changelog' in rule:
            for i in (rule['changelog']['changes']):
                if i['updated'] == updated and i['doc_text'] != "Formatting only.":
                    linkString = re.sub(' ', '-', rule['name'].lower())
                    linkString = re.sub('[():]', '', linkString)
                    linkString = re.sub('-+', '-', linkString)
                    linkString = re.sub('/', '-', linkString)
                    versionHistoryPage = versionHistoryPage + "<<" + linkString + ">>\n\n"

addVersionUpdates("7.9.0")
addVersionUpdates("7.8.0")
addVersionUpdates("7.7.0")
addVersionUpdates("7.6.2")
addVersionUpdates("7.6.1")                    



fileWrite = "generated-ascii-files" + "/" + "prebuilt-rules-changelog.asciidoc"
with open(fileWrite, "w") as writeFile:
        writeFile.write(versionHistoryPage)
