import xml.etree.ElementTree as ET
from typing import Any


def obj_to_xml(obj: Any) -> str:
    """Return an XML representation of the given object (dict, list, or primitive).
    Does NOT add a common root element if the given obj is a list.
    Does NOT work for nested dict structures."""
    if isinstance(obj, list):
        return "".join([obj_to_xml(o) for o in obj])
    if isinstance(obj, dict):
        return "".join(["<{k}>{v}</{k}>".format(k=k, v=obj_to_xml(v)) for (k, v) in obj.items()])
    return str(obj)


def strip_xmlns(obj: Any) -> Any:
    """Strip xmlns attributes from a dict returned by xmltodict.parse."""
    if isinstance(obj, list):
        return [strip_xmlns(item) for item in obj]
    if isinstance(obj, dict):
        # Remove xmlns attribute.
        obj.pop("@xmlns", None)
        if len(obj) == 1 and "#text" in obj:
            # If the only remaining key is the #text key, elide the dict
            # entirely, to match the structure that xmltodict.parse would have
            # returned if the xmlns namespace hadn't been present.
            return obj["#text"]
        return {k: strip_xmlns(v) for k, v in obj.items()}
    return obj


def is_valid_xml(xml_string: str) -> bool:
    """
    Check if the given string is a valid XML document.
    """
    try:
        # Attempt to parse the XML string
        ET.fromstring(xml_string.encode("utf-8"))
        return True
    except ET.ParseError:
        return False
