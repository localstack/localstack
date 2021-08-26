# FIXME: remove once fully migrated to new cli
import warnings

from localstack.cli.main import main as cli_main

warnings.simplefilter("always", DeprecationWarning)
warnings.warn(
    "%s is deprecated in favor of localstack.cli.main" % __name__, DeprecationWarning, stacklevel=2
)


def main():
    cli_main()


if __name__ == "__main__":
    main()
