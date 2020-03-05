---
name: Documentation Issue
about: Describe your Elastic security documentation issue.
title: ''
labels: ''
assignees: ''

---

## Description 

[insert a summary of the doc issue here. Background information is especially useful]. 

## Acceptance Test Criteria

List all the ATC of each action and its intended result. 
As a user, when [action (e.g., viewing, clicking, selecting, etc.)] the [insert the expected result]. 
If the doc issue includes a procedure, number the steps in sequential order.  

## Notes

Add the **"Team:Docs"** label to new issues. 
Be sure to add any necessary screenshots for clarity. 
Include any conditions or caveats that may affect customers. 

### Example Issue: 
**Issue Name:** Document the ability for users to disable artifact updates. 

**Description:** Many organizations have major events where they lock down updates to their systems. They lock down the updates because the systems are highly tuned and they don't want to introduce error or risk during the major event (think World Series or All Star Game or a state government just before elections.) This feature will give admin users the ability to stop artifact updates until that event is over and then re-enable after.

**Acceptance Test Criteria:** Ensure the user is logged into the platform as an admin. 
1. On the Left Navigation toolbar, click the Administration button, then select the **PLATFORM** tab.
2. In the "ARTIFACT UPDATE CONFIGURATION" section, click **Disable artifact updates**.
3. In the dialog box that says, "You are about to DISABLE artifact updates. This will prevent you from receiving updated artifacts..." click **Disable**. A 'Successfully updated configuration" confirmation appears.
4. Click **Finish**.
**Note:** To re-enable cloud updates, follow the aforementioned steps, except in Step 2, click **Enable artifact updates**.


