from .localstack import create_with_plugins


def main():
    cli = create_with_plugins()
    cli()


if __name__ == "__main__":
    main()
