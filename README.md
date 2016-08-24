# LocalStack - A fully functional local AWS cloud stack

*LocalStack* provides an easy-to-use test/mocking framework for developing Cloud applications.

Currently, the focus is primarily on supporting the AWS cloud stack.

*LocalStack* spins up the following Cloud APIs:

* **Api Gateway** at http://localhost:4567
* **Kinesis** at http://localhost:4568
* **DynamoDB** at http://localhost:4569
* **DynamoDB Streams** at http://localhost:4570
* **Elasticsearch** at http://localhost:4571
* **S3** at http://localhost:4572
* **Firehose** at http://localhost:4573
* **Lambda** at http://localhost:4574

## Requirements

* `make`
* `python`
* `pip` (python package manager)
* `npm` (node.js package manager)
* `java`/`javac` (Java runtime environment and compiler)

## Installation

To install the tool, run the following command:

```
make install
```

This will install the required pip dependencies in a local Python virtualenv directory 
`.venv` (your global python packages will remain untouched), as well as some node modules
in `./localstack/node_modules/`. Depending in your system, some pip/npm modules may require
additional native libs installed.

## Testing

The project comes with a set of unit and integration tests which can be kicked off via a make
target:

```
make test
```

## Running

The Makefile contains a target to conveniently run the local infrastructure.

```
make infra
```

Then you can point your `aws` CLI to use the local infrastructure, for example:

```
aws --endpoint-url=http://localhost:4568 kinesis list-streams
{
    "StreamNames": []
}
```

If you want to use *LocalStack* in your integration tests, simply fire up the
infrastructure in your test setup method:

```
infra.start_infra(async=True)
```

See the example test file `tests/test_integration.py` for more details.

## Web Dashboard

The projects also comes with a simple Web dashboard that allows to view the
deployed AWS components and the relationship between them.

```
make install-web
make web
```

## License

Copyright (c) 2016 Atlassian and others.

*LocalStack* is released under the Apache License, Version 2.0 (see LICENSE.txt).

We build on a number of third-party software tools, with the following licenses:

Third-Party software		| 	License
----------------------------|-----------------------
**Python/pip modules:**		|
t.b.a.						|