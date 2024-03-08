# Elastic Security docs

Elastic Security Docs home page: https://www.elastic.co/guide/en/security/current/index.html

Documentation Manager: Janeen Roberts (Github: `@jmikell821`)


## Contributing to Elastic Security docs

If you are an Elastic employee and would like to contribute to Elastic Security documentation: 

1. Please clone and fork the `security-docs` repo. 
2. Open an issue using the appropriate [template](https://github.com/elastic/security-docs/issues/new/choose).
3. Check out the `main` branch and fetch the latest changes. 
4. Check out a new branch and make your changes. 
5. Save your changes and open a pull request. 
6. Add the [@elastic/security-docs](https://github.com/orgs/elastic/teams/security-docs) team and any other appropriate members as reviewers. 
7. Add the appropriate release version label, backport version label if appropriate, and team label to the PR. 
8. Once the docs team approves all changes, you can merge it. If a backport version label was added to a PR for stack versions 7.14.0 and newer, mergify will automatically open a backport PR. 
9. Merge the backport PR once it passes all CI checks. 

### Preview documentation changes

When you open a pull request, preview links are automatically added as a comment in the PR. Once the CI check builds successfully, the links will be live and you can click them to preview your changes.

You also might want to add targeted links to help reviewers find specific pages related to your PR. Preview URLs include the following pattern (replace `<YOUR_PR_NUMBER_HERE>` with the PR number):

```
https://security-docs_bk_<YOUR_PR_NUMBER_HERE>.docs-preview.app.elstc.co/guide/en/security/master/
```
