import os
import pathlib

def handler(event, context):

    if event["action"] == "check":
        print("Checking file system")
        # TODO: build a dict :)
        tmp = pathlib.Path("/tmp")
        entries = []
        for a in tmp.glob("*"):

            print(f"{a=}")
            entries.append(f"{a=}")
        return entries

    elif event["action"] == "modify":
        print("Modifying file system")
        with open("/tmp/hello_world", "w") as fd:
            fd.write("hello")

        nested_dir = "/tmp/nested"
        os.mkdir(nested_dir)
        with open(os.path.join(nested_dir, "nested_file"), "w") as fd:
            fd.write("hello2")
        return "ok"
    else:
        raise Exception("Unknown action in payload")
