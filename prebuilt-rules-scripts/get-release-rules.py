import json
import os
import glob
from pathlib import Path
import re

# Creates a JSON file with all the prebuilt rules for the release. Before  
# running this script make sure the correct Kibana branch is checkout out.

releaseVersion = "7.9.1" # Security app release version - update as required

def sort_by_name(rule):
    '''
    Helper to sort rule by name'''
    return rule['name']


ruleSourceFolder = "../../kibana/x-pack/plugins/security_solution/server/lib/detection_engine/rules/prepackaged_rules/*.json"

rule_dict = []

ruleFiles = [f for f in glob.glob(ruleSourceFolder)]

for file in ruleFiles:
    with open (file, "r") as ruleFile:
        ruleJSON = json.load(ruleFile)
        rule_dict.append(ruleJSON)

rule_dict = sorted(rule_dict, key=sort_by_name)

with open("orig-rules-json-files/" + releaseVersion + "-prebuilt-rule.json", "w") as fp:
    json.dump(rule_dict, fp, indent=2)
