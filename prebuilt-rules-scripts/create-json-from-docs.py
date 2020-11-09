import json
import textwrap
import toml
import os
import glob
from pathlib import Path
import re

# Creates a JSON file from the existing prebuilt rules documentation and saves
# it in the diff-files folder.

releaseVersion = "7.10.0" #Security app release version - update as required

def sort_by_name(rule):
    '''
    Helper to sort rule by name'''
    return rule['name']
    
docSourcePath = "../docs/detections/prebuilt-rules/rule-details/*.asciidoc"

rule_dict = []
    
files = [f for f in glob.glob(docSourcePath)]

name = ""
description = ""
falsePos = ""
notes = ""

isDesc = False
isFalsePos = False
isNotes = False

counter = 0

for file in files:
    with open(file, "r") as docFile:
        text = docFile.readlines()
        for count, line in enumerate(text):
            if count == 1:
                name = line.split("=== ")[1].replace("\n", "")
                isDesc = True
            if isDesc:
                description = description + line
                if "*Rule type*" in text[count + 1]:
                    isDesc = False
            if "==== Potential false positives" in line:
                isFalsePos = True
                continue
            if isFalsePos:
                falsePos = falsePos + line
                if ("==== Rule query" in text[count]) or ("==== Investigation guide" in text[count]) or ("==== Rule version history" in text[count]):
                    isFalsePos = False
            if "==== Investigation guide" in line:
                isNotes = True
                continue
            if isNotes:
                notes = notes + line
        isNotes = False
        isFalsePos = False
        description = description.split("\n\n", 1)[1].replace("\n\n", "\n").rstrip()
        if "[[" in notes:
            notes = notes.split("[[")[0]
        if "\n==== Rule query\n" in notes:
            notes = notes.split("\n==== Rule query\n")[0]
        if "==== Rule query\n" in falsePos:
            falsePos = falsePos.split("\n\n==== Rule query\n")[0]
        if "==== Investigation guide\n" in falsePos:
            falsePos = falsePos.split("\n\n==== Investigation guide\n")[0]
        if "[[" in falsePos:
            falsePos = falsePos.split("[[")[0]
        falsePos = falsePos.rstrip()
        if falsePos != "" and notes == "":
            falsePos = falsePos.split("\n", 1)[1]
            rule_text = {"name": name, "description": description, "false_positives": [falsePos]}
        if falsePos == "" and notes == "":
            rule_text = {"name": name, "description": description}
        if falsePos == "" and notes != "":
            notes = notes.rstrip()
            notes = notes.split("\n", 1)[1]
            rule_text = {"name": name, "description": description, "note": notes}
        if falsePos != "" and notes != "":
            notes = notes.rstrip()
            notes = notes.split("\n", 1)[1]
            falsePos = falsePos.split("\n", 1)[1]
            rule_text = {"name": name, "description": description, "false_positives": [falsePos], "note": notes}
        rule_dict.append(rule_text)
        name = ""
        description = ""
        type = ""
        falsePos = ""
        notes = ""

# Update the file name below to indicate this JSON file is the currently
# existing docs

rule_dict = sorted(rule_dict, key=sort_by_name)

with open("diff-files/gen-files/json-from-docs-" + releaseVersion + ".json", "w") as fp:
    json.dump(rule_dict, fp, indent=2)
