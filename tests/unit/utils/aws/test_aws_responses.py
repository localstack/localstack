import xml.etree.ElementTree as ET

from localstack.utils.aws.aws_responses import to_xml


def test_to_xml():
    response = {
        "DescribeChangeSetResult": {
            # ...
            "Changes": [
                {
                    "ResourceChange": {
                        "Replacement": False,
                        "Scope": ["Tags"],
                    },
                    "Type": "Resource",
                }
            ]
        }
    }

    result = to_xml(response)
    result_str = str(ET.tostring(result))
    assert (
        "<member><ResourceChange><Replacement>False</Replacement><Scope><member>Tags</member></Scope></ResourceChange><Type>Resource</Type></member>"
        in result_str
    )
