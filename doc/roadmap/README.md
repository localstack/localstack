# LocalStack Roadmap

**UPDATE: This document is outdated. We are working on an updated roadmap which will be
published here and on the LocalStack website: [http://localstack.cloud](http://localstack.cloud)**

## Main Streams of Work

The following list is an attempt to summarize the main streams of work in *LocalStack* (in no particular order):

1. Support for Different Platforms

   Although running *LocalStack* in Docker is a good common denominator for cross-platform compatibility, there are always
   subtle differences between environments (e.g., mounting of volumes into the container, running Docker containers from
   within a container, etc). We need to make sure that *LocalStack* is truly platform independent and can be used
   (although MacOS/Linux will remain the main target platforms).

2. API Feature Parity

   The AWS APIs/services are constantly evolving and sometimes have very complex and detailed semantics. Users may rely
   on the exact semantics of an API, hence we should strive for the maxiumum possible parity of the mocks with the real
   services.

3. Upstream Issues

   We receive a significant amount of bug requests (and feature requests) from the community that are actually related
   to our upstream dependencies. In particular, a majority of our API mocks are based on
   [moto](https://github.com/spulec/moto), hence users will often raise a request in *LocalStack* if they discover an
   issue in one of the API mocks provided by moto. Some of the issues should be fixed upstream, in some cases it is more
   advisable to add a fix directly into *LocalStack*. This has to be decided on a case-by-case basis, but ideally we
   would want to define guidelines around that.

4. Integrations

   Integrations between the APIs/services are essential to support testing of any non-trivial cloud application. We
   currently have some of the basic integrations set up (e.g., Kinesis to Lambda, S3 bucket notifications to SQS/SNS,
   DynamoDB Streams to Kinesis), but we have a long way to go to provide the "full" set of integrations.

5. Extensibility / Developer Documentation

   In order to attract more contributions from the community, we need to clearly document how developers can extend
   and develop new features for *LocalStack*.

6. Support for Different Languages / SDKs

   Developers are using LocalStack in very different ways, using different languages and SDKs (Python, Java,\
   Node.js, Go), different testing frameworks (e.g., nosetests, JUnit), etc. We need to ensure a smooth developer
   experience for the mainstream . This is related to "Support for Different Platforms".

7. Extended Test Features

   Applications in a real cloud environments are often exposed to various exceptional situations and intermittent
   runtime problems, such as DNS issues, API throttling errors, etc. By adding support for injecting faults into Kinesis
   (`KINESIS_ERROR_PROBABILITY`) and DynamoDB (`DYNAMODB_ERROR_PROBABILITY`) we have only just scratched the surface of
   what can and should be done regarding systematic resilience testing.

8. Test Coverage

   The *LocalStack* codebase currently only has a limited set of tests (mainly integration tests), and overall test
   coverage should be improved. To achieve a certain level of quality assurance and API parity, we could employ
   automated Pact/schema/contract based testing.

9. Use Cases and Demos

   Make the framework available to a wider audience and showcase the usefulness based on real-world scenarios. Give demos
   and talks at conferences/summits, publish blog posts with success stories, customer use cases, etc.

## Priorities and Timelines

t.b.a.
