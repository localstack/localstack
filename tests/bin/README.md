# BATS bash tests

The tests in this folder are not regular Pytest tests.
They are implemented with [BATS](https://github.com/bats-core/bats-core) to test scripts in the `bin` folder of this repo.

## Prerequisites

**Install BATS**: If you don't have BATS installed, you need to install it first. On a Unix-like system, you can usually install it using a package manager.

For Debian-based systems (e.g., Ubuntu):
```bash
sudo apt-get update
sudo apt-get install bats
```

For macOS using Homebrew:
```bash
brew install bats-core
```

Alternatively, you can install BATS manually by cloning the repository and adding the `bin` folder to your `PATH` environment variable.
```bash
git clone https://github.com/bats-core/bats-core.git
cd bats-core
sudo ./install.sh /usr/local
```

## Writing tests

Create a file with a `.bats` extension, for example, `test_example.bats`. Here’s a simple test file:

```bash
#!/usr/bin/env bats
@test "test description" {
  run echo "hello"
  [ "$status" -eq 0 ]
  [ "$output" = "hello" ]
}
```

## Running Tests
To run the tests, simply execute the bats command followed by the test file or directory containing test files:

```bash
bats test_example.bats
```

You can also run all `.bats` files in a directory:

```bash
bats tests/bin
```

To run with some debug information, you can use this:

```bash
bats --trace --verbose-run --print-output-on-failure -r tests/bin/
```