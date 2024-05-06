---
title: "Contributing to LocalStack"
weight: 3
description: >
  Get started with contributing to LocalStack and help us grow the project and the community.
aliases:
  - /developer-guide/contributing/
---

LocalStack is a community driven project that aims to help developers emulate AWS services locally, without connecting to any cloud provider! The community version of LocalStack has grown exceptionally and now supports various AWS services, which is detailed on our  [feature coverage](https://docs.localstack.cloud/aws/feature-coverage/).

This document serves the need for a guide for contributors to help them understand the overall organization of the LocalStack community projects. As an emerging open-source community, we have a plethora of work that we need to do and complete, and it is not just limited to code.

From a contribution perspective, you can work on writing examples, triaging issues and pull requests, submitting bug fixes, suggesting improvements and making our documentation accessible to more users.

## Prerequisites

Before submitting any contributions to LocalStack, you should complete the following prerequisties. Having completed and understood the basic philosophy around these steps would make it easier for you to land your first contribution.

### Code of conduct

LocalStack governs its participants according to the Contributor Covenant  [Code of Conduct](https://github.com/localstack/.github/blob/main/CODE_OF_CONDUCT.md). As a contributor, you agree to uphold this code. Please report unacceptable behavior to  [info@localstack.cloud](mailto:info@localstack.cloud).

### Setup the development environment

To contribute code contributions, setting up a development environment is required. Review the  [LocalStack developer guide](https://docs.localstack.cloud/developer-guide/)  to understand how you can setup the environment and make the desirable changes. It is also recommended to look at our  [open issues](https://github.com/localstack/localstack/issues)  for better context around contributions we are looking for.

### Licensing

When you submit changes, your submissions are understood to be under the same [Apache 2.0 License](https://github.com/localstack/.github/blob/main/LICENSE)  that covers the project. Feel free to contact the maintainers if that's a concern.

## Contribution flow

We assume that you have already set up the project on your local machine by following up on the official development environment setup guide. If you are stuck, do reach out to one of the maintainers to help you out in the process.

Our contribution flow is very straightforward and follows an issue-pull request workflow. The contributors need to fork the repository for having their contributions landed on the project. If you are looking to contribute, we have laid down a series of steps that we would like you to follow.

### Find an issue to work on

We would recommend you to go through the  **Issues**  of the specific project that you would like to contribute to. You can additionally:

-   Understand and identify the gaps in the code and documentation.
-   Understand the code formatting, stylistic principles and comment format that is being followed.
-   Test specific pull requests and the project on your local machine and see if the changes are desirable.

Exploring the issues and pull requests, will give you an idea of how the contribution flow works. Upon finding something to work on, you can either request for the issue to be assigned to you (if someone else has created the Issue) or you can make your own. To ensure that the issue is received positively by the maintainers make sure of the following:

-   If you are filing a Bug report, make sure that the report includes all the information that the maintainer needs to reproduce the issue.
-   If you are filing a feature request, make sure you pitch in your idea well and it should be constructive.
-   Before opening a new issue, make sure a similar one has not already been created or is being worked on by someone else.

Alternatively, you can check out the [good first issues](https://github.com/localstack/localstack/labels/good%20first%20issue) label on the repository. These issues are meant to be a good starting point for new contributors. If you are interested to work on a particular service, check the [issue related to the particular service](https://github.com/localstack/localstack/labels?q=aws%3A) and the [associated API coverage](https://docs.localstack.cloud/localstack/coverage/). You can implement a method (or group of methods) that’s still missing, or add snapshot tests to increase the parity coverage.

### Landing your pull request

To make sure you land a great contribution, we would request you to follow the standard Git & GitHub workflow to know about code collaboration. If you are not already familiar with Git, we would suggest you follow the  [official Git documentation](https://git-scm.com/doc).

We would recommend:

-   Every Pull Request should have the corresponding issue linked to it.
-   Every Pull Request should pass the automated CI checks.
-   Every Pull Request should be as atomic as possible.
-   Every Pull Request should include a test verifying the new/fixed behavior.

Atomic commits correspond to the smallest, most meaningful change you can make to the code. You can keep your pull request as a draft if you are still working on it. Upon completion, you can mark the pull request is ready to review for further comments and feedback.

Every PR should demonstrate that the change works. Tests play an especially important role when we develop AWS service emulators. To get started with writing LocalStack tests, have a look at our testing guide. We would also like if tests are using [snapshot testing](https://localstack.cloud/blog/2022-08-04-parity-explained/#parity-tests-with-snapshot-testing). Additionally, 
run formatting and linting locally: `make format` and `make lint` on your changes to ensure that the linting checks don't fail.

### Reviewing pull requests

After landing your pull request, the codeowners will be automatically assigned who will review it and provide actionable feedback. Don't hesitate to contact the maintainers on the Slack community if you are awaiting your first review or you have made all the required changes.

Maintainers expect the comments to be resolved once a review has been completed. You can provide updates if you are still working on it, to help us understand the areas where we can help.
LocalStack uses a squash-merge workflow. After the pull request is reviewed and approved, we squash all commits in the PR to a single commit before we officially merge it.
