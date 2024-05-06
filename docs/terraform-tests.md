---
title: "Terraform test suite"
weight: 10
description: >
  How to run the Terraform test suite.
aliases:
  - /developer-guide/terraform-tests/
---

We regularly run the test suite of the Terraform AWS provider against LocalStack to test the compatibility of LocalStack to Terraform. To achieve that, we have a dedicated [GitHub action](https://github.com/localstack/localstack-terraform-test/blob/main/.github/workflows/main.yml) on [LocalStack](https://github.com/localstack/localstack), which executes the allow listed set of tests of [hashicorp/terraform-provider-aws](https://github.com/hashicorp/terraform-provider-aws/).
