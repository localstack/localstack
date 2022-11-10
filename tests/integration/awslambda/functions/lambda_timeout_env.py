import logging
import time

INTERNAL_NUMBER = 0


def handler(event, context):
    if write_content := event.get("write-file"):
        with open("/tmp/temp-store", mode="wt") as f:
            f.write(write_content)
    elif event.get("read-file"):
        with open("/tmp/temp-store", mode="rt") as f:
            return {"content": f.read(write_content)}
    elif new_num := event.get("set-number"):
        global INTERNAL_NUMBER
        INTERNAL_NUMBER = new_num
    elif event.get("read-number"):
        return {"number": INTERNAL_NUMBER}
    elif sleep_time := event.get("sleep"):
        try:
            print("starting wait")
            time.sleep(sleep_time)
            print("done waiting")
        except Exception as e:
            print("exception while waiting")
            logging.error(e)
