# Elastic Security docs

Elastic Security Docs home page: https://www.elastic.co/guide/en/security/current/index.html

Serverless docs: https://docs.elastic.co/serverless/security/what-is-security-serverless

Documentation Manager: Janeen Roberts (Github: `@jmikell821`)


## Contributing to Elastic Security docs

You can open an issue using the appropriate [template](https://github.com/elastic/security-docs/issues/new/choose).

> [!NOTE]
> Please report any **known issues** that need to be documented by creating an issue in our [private repo](https://github.com/elastic/security-docs-internal/issues) using the known issue template.

To contribute directly to Elastic Security documentation:

1. Please fork and clone the `security-docs` repo.
1. Check out the `main` branch and fetch the latest changes.
1. Check out a new branch and make your changes.
1. Save your changes and open a pull request.
1. Add all appropriate Github users as reviewers.
1. Add the appropriate release version label, backport version label if appropriate, and team label to the PR.
1. Once the docs team approves all changes, you can merge it. If a backport version label was added to a PR for stack versions 7.14.0 and newer, mergify will automatically open a backport PR.
1. Merge the backport PR once it passes all CI checks.

### Preview documentation changes

When you open a pull request, preview links are automatically added as a comment in the PR. Once the CI check builds successfully, the links will be live and you can click them to preview your changes.

You also might want to add targeted links to help reviewers find specific pages related to your PR. Preview URLs include the following pattern (replace `<YOUR_PR_NUMBER_HERE>` with the PR number):

```
https://security-docs_bk_<YOUR_PR_NUMBER_HERE>.docs-preview.app.elstc.co/guide/en/security/master/
```

## License

Shield: [![CC BY-NC-ND 4.0][cc-by-nc-nd-shield]][cc-by-nc-nd]

This work is licensed under a
[Creative Commons Attribution-NonCommercial-NoDerivs 4.0 International License][cc-by-nc-nd].

[![CC BY-NC-ND 4.0][cc-by-nc-nd-image]][cc-by-nc-nd]

[cc-by-nc-nd]: http://creativecommons.org/licenses/by-nc-nd/4.0/
[cc-by-nc-nd-image]: https://licensebuttons.net/l/by-nc-nd/4.0/88x31.png
[cc-by-nc-nd-shield]: https://img.shields.io/badge/License-CC%20BY--NC--ND%204.0-lightgrey.svg