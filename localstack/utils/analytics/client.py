"""
Client for the analytics backend.
"""
import logging
from typing import Any, Dict, List

import requests

from localstack import config, constants
from localstack.utils.http import get_proxies
from localstack.utils.time import now

from .events import Event, EventMetadata
from .metadata import ClientMetadata, get_session_id

LOG = logging.getLogger(__name__)


class SessionResponse:

    response: Dict[str, Any]

    def __init__(self, response: Dict[str, Any]):
        self.response = response

    def track_events(self) -> bool:
        return self.response.get("track_events")


class AnalyticsClient:
    api: str

    def __init__(self, api=None):
        self.api = (api or constants.ANALYTICS_API).lstrip("/")
        self.debug = config.DEBUG_ANALYTICS

        self.endpoint_session = self.api + "/session"
        self.endpoint_events = self.api + "/events"

        self.localstack_session_id = get_session_id()

    def start_session(self, metadata: ClientMetadata) -> SessionResponse:
        # FIXME: re-using Event as request object this way is kind of a hack
        request = Event(
            "session", EventMetadata(self.localstack_session_id, str(now())), payload=metadata
        )

        response = requests.post(
            self.endpoint_session,
            headers=self._create_headers(),
            json=request.asdict(),
            proxies=get_proxies(),
        )

        if not response.ok:
            raise ValueError("error during session initiation with analytics backend")

        return SessionResponse(response.json())

    def append_events(self, events: List[Event]):
        # TODO: add compression to append_events
        #  it would maybe be useful to compress analytics data, but it's unclear how that will
        #  affect performance and what the benefit is. need to measure first.

        endpoint = self.endpoint_events

        if not events:
            return

        docs = []
        for event in events:
            try:
                docs.append(event.asdict())
            except Exception:
                if self.debug:
                    LOG.exception("error while recording event %s", event)

        headers = self._create_headers()

        if self.debug:
            LOG.debug("posting to %s events %s", endpoint, docs)

        # FIXME: fault tolerance/timeouts
        response = requests.post(
            endpoint, json={"events": docs}, headers=headers, proxies=get_proxies()
        )

        if self.debug:
            LOG.debug("response from %s was: %s %s", endpoint, response.status_code, response.text)

        # TODO: Add response type to analytics client
        return response

    def _create_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": "localstack/" + constants.VERSION,
            "Localstack-Session-ID": self.localstack_session_id,
        }
