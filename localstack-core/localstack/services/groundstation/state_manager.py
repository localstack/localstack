"""Contact state manager for automatic state transitions.

This module manages automatic contact state transitions based on scheduled times:
- SCHEDULED → PASS (when start time arrives)
- PASS → COMPLETED (when end time arrives)
"""

import logging
import threading
import time
from datetime import UTC, datetime

from localstack.aws.api.groundstation import ContactStatus
from localstack.services.groundstation.models import ContactData, groundstation_stores

LOG = logging.getLogger(__name__)


class ContactStateManager:
    """Manages automatic state transitions for scheduled contacts.

    This background thread periodically checks all contacts and transitions
    their states based on current time:

    - SCHEDULED → PASS: When current time >= start_time
    - PASS → COMPLETED: When current time >= end_time

    The manager runs in a background thread and checks every 5 seconds by default.
    """

    def __init__(self, check_interval: int = 5):
        """Initialize the contact state manager.

        Args:
            check_interval: Seconds between state checks (default: 5)
        """
        self.check_interval = check_interval
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the background state management thread."""
        with self._lock:
            if self._running:
                LOG.warning("ContactStateManager already running")
                return

            self._running = True
            self._thread = threading.Thread(
                target=self._run_state_manager,
                name="ContactStateManager",
                daemon=True,
            )
            self._thread.start()
            LOG.info("ContactStateManager started with check interval: %ds", self.check_interval)

    def stop(self) -> None:
        """Stop the background state management thread."""
        with self._lock:
            if not self._running:
                return

            self._running = False
            if self._thread:
                self._thread.join(timeout=10)
                self._thread = None
            LOG.info("ContactStateManager stopped")

    def is_running(self) -> bool:
        """Check if the state manager is currently running."""
        return self._running

    def _run_state_manager(self) -> None:
        """Background thread that periodically checks and updates contact states."""
        LOG.debug("ContactStateManager thread started")

        while self._running:
            try:
                self._check_and_update_contacts()
            except Exception as e:
                LOG.exception("Error in ContactStateManager: %s", e)

            # Sleep in small intervals to allow quick shutdown
            for _ in range(self.check_interval):
                if not self._running:
                    break
                time.sleep(1)

        LOG.debug("ContactStateManager thread stopped")

    def _check_and_update_contacts(self) -> None:
        """Check all contacts and update their states based on current time."""
        now = datetime.now(UTC)
        updated_count = 0

        # Get all contacts (across all accounts/regions)
        contacts = self._get_all_contacts()

        for contact_id, contact in contacts.items():
            try:
                old_status = contact.contact_status
                new_status = self._calculate_new_status(contact, now)

                if new_status and new_status != old_status:
                    contact.contact_status = new_status
                    contact.updated_at = now
                    updated_count += 1
                    LOG.info(
                        "Contact %s transitioned: %s → %s",
                        contact_id,
                        old_status.value,
                        new_status.value,
                    )

            except Exception as e:
                LOG.exception("Error updating contact %s: %s", contact_id, e)

        if updated_count > 0:
            LOG.debug("Updated %d contact(s)", updated_count)

    def _get_all_contacts(self) -> dict[str, ContactData]:
        """Get all contacts from the store.

        Returns:
            Dictionary mapping contact_id to ContactData
        """
        try:
            # Access the LocalAttribute which handles account/region isolation
            return dict(groundstation_stores.contacts)
        except Exception as e:
            LOG.error("Error accessing contact store: %s", e)
            return {}

    def _calculate_new_status(self, contact: ContactData, now: datetime) -> ContactStatus | None:
        """Calculate the new status for a contact based on current time.

        State transition rules:
        - SCHEDULED → PASS: when now >= start_time
        - PASS → COMPLETED: when now >= end_time
        - Other states remain unchanged

        Args:
            contact: The contact to check
            now: Current time

        Returns:
            New status if transition should occur, None otherwise
        """
        current_status = contact.contact_status

        # Only transition SCHEDULED and PASS states
        if current_status not in [ContactStatus.SCHEDULED, ContactStatus.PASS]:
            return None

        # Make times timezone-aware if they aren't already
        start_time = (
            contact.start_time.replace(tzinfo=UTC)
            if contact.start_time.tzinfo is None
            else contact.start_time
        )
        end_time = (
            contact.end_time.replace(tzinfo=UTC)
            if contact.end_time.tzinfo is None
            else contact.end_time
        )

        # PASS → COMPLETED: Contact has ended
        if current_status == ContactStatus.PASS and now >= end_time:
            return ContactStatus.COMPLETED

        # SCHEDULED → PASS: Contact has started
        if current_status == ContactStatus.SCHEDULED and now >= start_time:
            return ContactStatus.PASS

        return None


# Global singleton instance
_contact_state_manager: ContactStateManager | None = None


def get_contact_state_manager() -> ContactStateManager:
    """Get or create the global ContactStateManager instance.

    Returns:
        The global ContactStateManager singleton
    """
    global _contact_state_manager
    if _contact_state_manager is None:
        _contact_state_manager = ContactStateManager()
    return _contact_state_manager


def start_contact_state_manager() -> None:
    """Start the global contact state manager."""
    manager = get_contact_state_manager()
    manager.start()


def stop_contact_state_manager() -> None:
    """Stop the global contact state manager."""
    manager = get_contact_state_manager()
    manager.stop()
