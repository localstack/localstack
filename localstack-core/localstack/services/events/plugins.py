from localstack.packages import Package, package


@package(name="event-ruler")
def event_ruler_package() -> Package:
    from localstack.services.events.packages import event_ruler_package

    return event_ruler_package
