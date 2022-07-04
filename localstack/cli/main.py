def main():
    # initialize repositories
    from .localstack import create_with_plugins

    cli = create_with_plugins()
    cli()


if __name__ == "__main__":
    main()
