This spec preserves the SQS query protocol spec, which was part of botocore until the protocol was switched to json with `botocore==1.31.81`.
This switch removed a lot of spec data which is necessary for the proper parsing and serialization, which is why we have to preserve them on our own.

- The spec content was preserved from this state: https://github.com/boto/botocore/blob/143e3925dac58976b5e83864a3ed9a2dea1db91b/botocore/data/sqs/2012-11-05/service-2.json
- This was the last commit before the protocol switched back (again) to query (with https://github.com/boto/botocore/commit/143e3925dac58976b5e83864a3ed9a2dea1db91b).
- The file is licensed with Apache License 2.0.
- Modifications:
  - Removal of documentation strings with the following regex: `(,)?\n\s+"documentation":".*"`
