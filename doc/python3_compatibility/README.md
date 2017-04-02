# Python 3 Compatibility

*LocalStack* currently requires a Python 2.x runtime and is not compatible with Python version 3.x.

With Python 2.x becoming "legacy" [1], we should work towards making *LocalStack* compatible with Python 3.x.

## Work Items

### Code-Level Changes

* Fix all code that is syntactically incompatible (e.g., convert `print foobar` to `print(foobar)`)

**TODO: add details**

### Libraries

We need to verify that all the libraries we depend on are Python 3 compatible.
If a library is not compatible, we need to find a replacement.

**TODO: add details**

## CI Builds

Our automated tests and builds should assert the version compatibility. Achieving high test coverage will be essential.
Ideally, we want to support 2.x and 3.x, but long-term we should aim primarily for 3.x compatibility.

## References

[1] https://wiki.python.org/moin/Python2orPython3
