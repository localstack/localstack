def main():
    # config profiles are the first thing that need to be loaded
    from .profiles import set_profile_from_sys_argv

    set_profile_from_sys_argv()

    # initialize CLI plugins
    from .localstack import create_with_plugins

    cli = create_with_plugins()
    cli()


if __name__ == "__main__":
    main()
