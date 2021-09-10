# this module fails when importing to test the fault tolerance of the plugin discovery mechanism


def fail():
    raise ValueError("this is an expected exception")


fail()
