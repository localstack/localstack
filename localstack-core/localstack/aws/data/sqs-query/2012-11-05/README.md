This spec preserves the SQS query protocol spec, which was part of botocore until the protocol was switched to json with `botocore==1.31.81`.
This switch removed a lot of spec data which is necessary for the proper parsing and serialization, which is why we have to preserve them on our own.

- The spec content was preserved from this state: https://github.com/boto/botocore/blob/79c92132e266b15f62bc743ae0816c27d598c36e/botocore/data/sqs/2012-11-05/service-2.json
- This was the last commit before the protocol switched back (again) to json (with https://github.com/boto/botocore/commit/47a515f6727a7585487d58c069c7c0063c28899e).
- The file is licensed with Apache License 2.0.
- Modifications:
  - Removal of documentation strings with the following regex: `(,)?\n\s+"documentation":".*"`
  - Added `MessageSystemAttributeNames` to `ReceiveMessageRequest.members` with AWS deprecating `AttributeNames`.
  The patches in `spec-patches.json` are not present in the boto client for our sqs-query tests right now because the custom loading is not fully integrated at the moment, so it is changed directly in the spec.
