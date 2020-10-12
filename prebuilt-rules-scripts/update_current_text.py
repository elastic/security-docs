import json
import textwrap
import toml
import os
import glob
from pathlib import Path
import re

releaseVersion = "7.9.1" #Security app release version - update as required

def sort_by_name(rule):
    '''
    Helper to sort rule by name'''
    return rule['name']
    
# Path to latest prebuilt rules JSON file

with open("orig-rules-json-files/" + releaseVersion + "-prebuilt-rule.json", "r") as source:
    currentText = json.load(source)

# Path to JSON file generated from existing documentation
    
with open("diff-files/gen-files/json-from-docs-" + releaseVersion + ".json", "r") as source:
    updatedText = json.load(source)

for rule in currentText:
    for newText in updatedText:
        if rule['name'] == newText['name']:
            rule['description'] = newText['description']
            if 'false_positives' in newText and 'false_positives' in rule:
                rule['false_positives'][0] = newText['false_positives'][0]
            if 'note' in newText:
                rule['note'] = newText['note']

# Output file with updated text from the documentation for previously existing
# prebuilt rules. New rules are unchanged.

with open("diff-files/gen-files/updated-text-json-file-" + releaseVersion + ".json", "w") as fp:
    json.dump(currentText, fp, indent=2)
            
