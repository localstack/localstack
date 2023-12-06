"""Helper script to retrieve historical data and load into tinybird parity dashboard

The script is intended to be run locally. It was executed once, to retrieve the data from the past successful master builds
in order to get more data into the parity dashboard for a hackathon project.

"""

import datetime
import http.client
import json
import os
import urllib

from scripts.tinybird.upload_raw_test_metrics_and_coverage import (
    send_implemented_coverage,
    send_metric_report,
)

PROJECT_SLUG = "github/localstack/localstack"
MASTER_BRANCH = "master"


def send_request_to_connection(conn, url):
    print(f"sending request to url: {url}")
    headers = {"accept": "application/json"}  # , "Circle-Token": api_token}
    conn.request(
        "GET",
        url=url,
        headers=headers,
    )

    res = conn.getresponse()
    if res.getcode() == 200:
        data = res.read()
        return data
    else:
        print(f"connection failed: {res.getcode}")
        return None


def extract_artifacts_url_for_path(artifacts, path):
    data_url = [item["url"] for item in artifacts["items"] if item["path"].startswith(path)]
    if len(data_url) != 1:
        print(f"unexpected artifacts count for {path}, unexpected content: {data_url}")
        return None
    return data_url[0]


def collect_workflows_past_30_days():
    """
    Retrieves the workflows run from the past 30 days from circecli on 'master' branch,
    and retrieves the artifacts for each successful workflow run, that are collected in the 'report' job.
    The artifacts for coverage implementation, and raw-data collection are downloaded, and then processed and sent to
    tinybird backend.
    """
    try:
        conn = http.client.HTTPSConnection("circleci.com")
        # api_token = os.getenv("API_TOKEN")

        end = datetime.datetime.utcnow()
        start = end - datetime.timedelta(days=30)

        get_workflows_request = f"/api/v2/insights/{PROJECT_SLUG}/workflows/main?&branch={MASTER_BRANCH}&start-date={start.isoformat()}&end-date={end.isoformat()}"

        data = send_request_to_connection(conn, get_workflows_request)

        if not data:
            print(f"could not resolve {get_workflows_request}")
            return

        # this is just for tracking the current status - we already uploaded data for all of these workflows-ids:
        already_sent = [
            "0b4e29e5-b6c2-42b6-8f2d-9bbd3d3bc8aa",
            "3780cc96-10a0-4c41-9b5a-98d16b83dd94",
            "7ec971e9-4ee2-4269-857e-f3641961ecde",
            "3e02b8c5-6c9b-40d0-84df-c4e2d0a7797d",
            "015202d7-5071-4773-b223-854ccffe969f",
            "c8dd0d5d-b00c-4507-9129-669c3cc9f55a",
            "a87bf4f8-3adb-4d0a-b11c-32c0a3318ee9",
            "0b1a2ddb-ed17-426c-ba0c-23c4771ecb22",
            "97d01dac-15a1-4791-8e90-ce1fed09538d",
            "83fb8b2f-dab2-465f-be52-83342820f448",
            "2ae81ec5-2d18-48bf-b4ad-6bed8309f281",
            "63aa8ee8-4242-43fa-8408-4720c8fdd04b",
            "32c09e00-0733-443e-9b3a-9ca7e2ae32eb",
            "e244742d-c90b-4301-9d0f-1c6a06e3eec9",
            "0821f4ca-640d-4cce-9af8-a593f261aa75",
            "b181f475-192c-49c5-9f80-f33201a2d11b",
            "90b57b93-4a01-4612-bd92-fe9c4566da64",
            "dd8e4e20-2f85-41d3-b664-39304feec01b",
            "6122ea91-f0e4-4ea4-aca6-b67feec9d81b",
            "c035931f-90b0-4c48-a82c-0b7e343ebf49",
            "d8b03fae-b7e2-4871-a480-84edd531bfb9",
            "f499c3c1-ac46-403a-8a73-2daaebcf063d",
            "a310a406-b37a-4556-89e3-a6475bbb114f",
            "bab3f52c-0ed2-4390-b4b4-d34b5cb6e1ad",
            "c2245fe6-258f-4248-a296-224fe3f213d1",
            "67e8e834-3ab6-497e-b2d3-1e6df4575380",
            "3b367c58-f208-4e98-aa92-816cd649094b",
            "cc63b1b1-61ff-44f9-b3bf-cc24e23cf54b",
            "4eff4f42-770e-414a-ad5d-dde8e49b244f",
            "8092d5a8-c9a8-4812-ac22-d620a5e04003",
            "d682debe-17d7-4e31-9df1-e2f70758302f",
            "b8a3e0ea-25ca-47df-afec-48ac3a0de811",
            "450f335f-cd9c-45f3-a69f-1db5f9f16082",
            "4467264f-8a57-4a05-ad0d-8d224221ec69",
            "9e91a4d6-147b-4a64-bcb6-2d311164c3d8",
            "4a0c989a-31e7-4d9d-afdc-dc31c697fd11",
            "5b1a604c-12a9-4b9c-ba1e-abd8be05e135",
            "a9291b6e-eefe-466f-8802-64083abbfb0f",
            "0210fe7b-55a9-4bb0-a496-fbbff2831dd5",
            "1d5056aa-4d8c-4435-8a90-b3b48c8849e6",
            "1b339b55-fd27-4527-aff3-4a31109297e4",
            "f9c79715-ff09-4a1a-acea-ac4acd0eedc4",
            "93cddbf6-b48d-4086-b089-869ff2b7af0f",
            "f96e2531-cde6-490f-be26-076b3b3deaa4",
            "2dec1ba3-c306-4868-95bf-668689c10f4f",
            "ce8bedd9-618c-4475-b76e-b429ac49f84b",
            "7f2ae078-41cd-4f64-88ec-ef0f45185020",
            "271ba76a-3c7d-4b6e-abbd-294050608ebf",
            "afa647e9-ad38-467f-9ebc-fa7283586c19",
            "2cef06d8-98dc-415e-a8af-758689711c68",
            "8c859042-b37a-4447-9d3e-07d1ae160765",
            "b5ba1234-1983-4805-a9be-c4ca9c52b799",
            "b6614e63-4538-4583-8f9d-0c220db602a8",
            "71453fae-a689-4e28-995f-bd6e2c7cadaf",
            "53e43bae-3c70-4df5-8490-fe9208fbd952",
            "d1776b0e-7ddc-42e0-bd2d-7561ae72ae8b",
            "ad88f81e-6526-44f4-9208-ea64efdbde87",
            "503226e6-6671-4248-9fba-7b31f4684c0c",
            "c8e688aa-b63d-4e11-a14e-4ea1a2ad5257",
            "48002330-8ecb-41c5-9acc-95ae260a7a15",
            "e5550424-bec4-48a1-9354-0ad1f14510c4",
            "304dc6fc-9807-46b6-9665-fe8d6cc2d9b7",
            "24fe00ef-6c48-4260-9bca-125e2b16e7b2",
            "12e6470d-f923-4358-9fbb-185ff981903c",
            "32b53e7f-f0d3-446b-9b56-9cb4cdd5134d",
            "fe786b67-dc09-41e0-aba5-33e7aa8dcdf7",
            "a7c06a4b-2954-4660-8072-3c10c7d2823b",
            "c1dedfce-2619-484b-8a10-bc9b2bda39ff",
            "618a7511-e82b-4e7f-9d4a-4b4a4247f6e0",
            "00bec0f4-7844-4ad9-8d01-e3833aae9697",
            "8cb2fb8f-b840-4f5b-b151-744fb425298c",
            "8c2a8d3d-f05a-4c27-9df6-bc7f4f6106b8",
            "9dfc79d6-952e-4ae4-9dd8-493ac9a30065",
            "edf9a307-0e80-4a80-97f4-f53c78910554",
            "3c9c12e5-0fe7-4b1a-b224-7570808f8e19",
        ]
        # TODO check "next_page_token"
        #  -> wasn't required for the initial run, as on master everything was on one page for the past 30 days
        workflows = json.loads(data.decode("utf-8"))
        count = 0
        for item in workflows.get("items"):
            if item["status"] == "success":
                workflow_id = item["id"]
                if workflow_id in already_sent:
                    continue
                print(f"checking workflow_id {workflow_id}")
                date_created_at = item["created_at"]
                converted_date = datetime.datetime.strptime(
                    date_created_at, "%Y-%m-%dT%H:%M:%S.%fZ"
                )
                # create the same time format we use when uploading data in the cirlce ci
                timestamp = converted_date.strftime("%Y-%m-%d %H:%M:%S")

                # get the details for the job (we need the job_number of the report step)
                job_request = f"/api/v2/workflow/{workflow_id}/job"
                job_data = send_request_to_connection(conn, job_request)
                if not job_data:
                    print("could not retrieve job_data")
                    return
                jobs = json.loads(job_data.decode("utf-8"))
                report_job = [item for item in jobs["items"] if item["name"] == "report"]
                if len(report_job) != 1:
                    print(f"report job should be exactly 1, unexpected content: {report_job}")
                    return
                job_number = report_job[0]["job_number"]

                # request artificats for the report job
                artifacts_request = (
                    f"/api/v2/project/github/localstack/localstack/{job_number}/artifacts"
                )
                artifacts_data = send_request_to_connection(conn, artifacts_request)
                if not artifacts_data:
                    print("could not retrieve artifacts data")
                    return

                artifacts = json.loads(artifacts_data.decode("utf-8"))

                # extract the required urls for metric-data-raw, and coverage data for community/pro
                metric_data_url = extract_artifacts_url_for_path(
                    artifacts=artifacts, path="parity_metrics/metric-report-raw-data-all"
                )
                community_cov_url = extract_artifacts_url_for_path(
                    artifacts=artifacts, path="community/implementation_coverage_full.csv"
                )
                pro_cov_url = extract_artifacts_url_for_path(
                    artifacts=artifacts, path="pro/implementation_coverage_full.csv"
                )

                if not metric_data_url or not community_cov_url or not pro_cov_url:
                    print("At least one artifact url could not be found. existing..")
                    return

                # download files locally
                metric_report_file_path = "./metric_report_raw.csv"
                print(f"trying to download {metric_data_url}")
                urllib.request.urlretrieve(metric_data_url, metric_report_file_path)

                community_coverage_file_path = "./community_coverage.csv"
                print(f"trying to download {community_cov_url}")
                urllib.request.urlretrieve(community_cov_url, community_coverage_file_path)

                pro_coverage_file_path = "./pro_coverage.csv"
                print(f"trying to download {pro_cov_url}")
                urllib.request.urlretrieve(pro_cov_url, pro_coverage_file_path)

                # update required ENVs with the data from the current workflow/job
                os.environ["CIRCLE_BRANCH"] = MASTER_BRANCH
                os.environ["CIRCLE_PULL_REQUESTS"] = ""
                os.environ["CIRCLE_BUILD_NUM"] = str(job_number)
                os.environ["CIRCLE_BUILD_URL"] = ""
                os.environ["CIRCLE_WORKFLOW_ID"] = str(workflow_id)

                # trigger the tinybird_upload
                send_metric_report(
                    metric_report_file_path, source_type="community", timestamp=timestamp
                )
                send_implemented_coverage(
                    community_coverage_file_path, timestamp=timestamp, type="community"
                )
                send_implemented_coverage(pro_coverage_file_path, timestamp=timestamp, type="pro")
                already_sent.append(workflow_id)
                count = count + 1
                # print(already_sent)

    finally:
        print(already_sent)
        if timestamp:
            print(f"last timestamp: {timestamp}")
        if count:
            print(f"sent {count} workflow data to tinybird")
        if conn:
            conn.close()


def main():
    collect_workflows_past_30_days()


if __name__ == "__main__":
    main()
