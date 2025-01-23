from localstack.packages import Package, package


@package(name="jpype-jsonata")
def jpype_jsonata_package() -> Package:
    """The Java-based jsonata library uses JPype and depends on a JVM installation."""
    from localstack.services.stepfunctions.packages import jpype_jsonata_package

    return jpype_jsonata_package
