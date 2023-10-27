#!/usr/bin/env python

import argparse
import json
import logging
import sqlite3
from collections import defaultdict

from localstack.utils.bootstrap import setup_logging

LOG = logging.getLogger("find_leaking_test_resources")

# TODO: be more sophisticated about pair matching, e.g. a CreateKey should be followed by a DeleteKey, a CancelKeyDeletion should be followed by a DeleteKey
METHOD_PAIRS = {
    "kms": {
        "create": [
            "CreateKey",
            "ReplicateKey",
            "CancelKeyDeletion",
        ],
        "delete": [
            "ScheduleKeyDeletion",
        ],
    },
    "dynamodb": {
        "create": ["CreateTable"],
        "delete": ["DeleteTable"],
    },
    "kinesis": {
        "create": ["CreateStream"],
        "delete": ["DeleteStream"],
    },
    "opensearch": {
        "create": ["CreateDomain"],
        "delete": ["DeleteDomain"],
    },
    "cloudformation": {
        "create": ["CreateStack", "CreateChangeSet"],
        "delete": ["DeleteStack", "DeleteChangeSet"],
    },
    "s3": {
        "create": ["CreateBucket"],
        "delete": ["DeleteBucket"],
    },
    "sns": {
        "create": ["CreateTopic"],
        "delete": ["DeleteTopic"],
    },
    "stepfunctions": {
        "create": ["CreateStateMachine"],
        "delete": ["DeleteStateMachine"],
    },
}

if __name__ == "__main__":
    setup_logging()

    parser = argparse.ArgumentParser()
    parser.add_argument("db")
    parser.add_argument("-o", "--output", type=argparse.FileType("w"), default="-")
    args = parser.parse_args()

    test_report = defaultdict(dict)
    missing_services = set()

    with sqlite3.connect(args.db) as conn:
        cursor = conn.cursor()
        cursor.execute("select test_key, api_calls from api_calls")

        for test_key, api_calls_raw in cursor:
            LOG.debug("test: %s", test_key)
            api_calls = json.loads(api_calls_raw)

            services = set(service for (service, operation, _) in api_calls)
            for tested_service in services:
                # skip services where we have not yet defined the method pairs
                if tested_service not in METHOD_PAIRS:
                    if tested_service not in missing_services:
                        LOG.warning("service %s not defined", tested_service)
                        missing_services.add(tested_service)
                    continue

                LOG.debug("testing %s", tested_service)
                called_methods = [
                    (service, operation)
                    for (service, operation, status_code) in api_calls
                    if service == tested_service and status_code < 400
                ]

                service_methods = METHOD_PAIRS[tested_service]

                created_score = len(
                    [
                        method
                        for (_, method) in called_methods
                        if method in service_methods["create"]
                    ]
                )
                deleted_score = len(
                    [
                        method
                        for (_, method) in called_methods
                        if method in service_methods["delete"]
                    ]
                )

                if created_score == deleted_score:
                    continue

                # special cases

                # cloudformation: DeleteStack is idempotent, so it may be called multiple times.
                if tested_service == "cloudformation" and created_score < deleted_score:
                    LOG.debug("cloudformation may perform multiple deletes")
                    continue

                outcome = (
                    "not enough deletes" if created_score > deleted_score else "too many deletes"
                )

                operations = [operation for (_, operation) in called_methods]
                test_report[test_key][tested_service] = {
                    "outcome": outcome,
                    "operations": [operation for (_, operation) in called_methods],
                }

                LOG.error(
                    "test %s has unbalanced resource creation with %s operations; %s: %s",
                    test_key,
                    tested_service,
                    outcome,
                    operations,
                )

        json.dump(test_report, args.output, indent=2)
