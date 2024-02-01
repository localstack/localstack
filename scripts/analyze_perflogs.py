#!/usr/bin/env python3
import glob
import json

import pandas as pd

PREFIX = "test-perf-timelog:"


def read_parse_file(file_name: str):
    with open(file_name, mode="rt") as f:
        logs = f.read()

    logs = logs.splitlines()

    resource_logs = [line for line in logs if PREFIX in line]

    resources = [
        json.loads(f"{line.partition(PREFIX)[2].rpartition('}')[0]}}}") for line in resource_logs
    ]
    return resources


def get_dataset(glob_str: str) -> pd.DataFrame:
    result = []
    for file in glob.glob(glob_str):
        result += read_parse_file(file)
    return pd.json_normalize(result)


# prepare dataset
base_df = get_dataset("./logs/base_perflog*.log")
new_df = get_dataset("./logs/new_perflog*.log")
print("base")
base_df.info()
print("new")
new_df.info()

merged_df = base_df.merge(new_df, how="outer", on="nodeid", suffixes=("_base", "_new"))
print("merged")
merged_df.info()

merged_df["diff"] = merged_df["timediff_new"] - merged_df["timediff_base"]
merged_df["diff_rel"] = (merged_df["timediff_new"] - merged_df["timediff_base"]) / merged_df[
    "timediff_base"
]

sorted_df = merged_df.sort_values(by="diff_rel", ascending=False)

print(sorted_df["timediff_new"].sum() - sorted_df["timediff_base"].sum())

big_differences = sorted_df[sorted_df["diff"] > 0.1]
# big_differences.info()
with pd.option_context(
    "display.max_rows",
    None,
    "display.max_columns",
    None,
    "display.max_colwidth",
    150,
    "display.expand_frame_repr",
    False,
):  # more options can be specified also
    pass
    # print(big_differences[["nodeid", "timediff_base", "timediff_new", "diff", "diff_rel"]])
