from tests.bootstrap.conftest import ContainerFactory


def test_defaults(container_factory: ContainerFactory):
    """
    The default configuration is to listen on 0.0.0.0:4566
    """
    container = container_factory()
    container.run(attach=False)
    container.wait_until_ready()

    print(10)
