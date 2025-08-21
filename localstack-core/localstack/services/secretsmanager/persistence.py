"""
Persistence implementation for AWS Secrets Manager.
This module provides concrete save/load functionality for persisting secrets across LocalStack restarts.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

from moto.core.base_backend import BackendDict
from moto.secretsmanager import secretsmanager_backends
from moto.secretsmanager.models import FakeSecret, SecretsManagerBackend

from localstack import config
from localstack.state import pickle
from localstack.state.core import StateVisitor

LOG = logging.getLogger(__name__)


class SecretsManagerSaveVisitor(StateVisitor):
    """Visitor that saves SecretsManager state to disk."""

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def visit(self, state_container: Any):
        """Save the SecretsManager backend state."""
        if isinstance(state_container, BackendDict):
            self._save_backend_dict(state_container)

    def _save_backend_dict(self, backend_dict: BackendDict):
        """Save the moto SecretsManager backend dict to disk."""
        try:
            # Extract the state we need to persist
            state_to_save = {}

            LOG.debug(f"Saving backend_dict with {len(backend_dict)} account(s)")

            for account_id, regions in backend_dict.items():
                state_to_save[account_id] = {}
                for region_name, backend in regions.items():
                    if isinstance(backend, SecretsManagerBackend):
                        # Extract secrets from the backend
                        secrets_data = {}
                        LOG.debug(
                            f"Saving {len(backend.secrets)} secret(s) for "
                            f"account {account_id}, region {region_name}"
                        )
                        for secret_id, secret in backend.secrets.items():
                            if isinstance(secret, FakeSecret):
                                # Save essential secret data
                                secrets_data[secret_id] = {
                                    "name": secret.name,
                                    "secret_id": secret.secret_id,
                                    "secret_string": secret.default_version_id
                                    and secret.versions.get(
                                        secret.default_version_id, {}
                                    ).get("secret_string"),
                                    "secret_binary": secret.default_version_id
                                    and secret.versions.get(
                                        secret.default_version_id, {}
                                    ).get("secret_binary"),
                                    "description": secret.description,
                                    "kms_key_id": secret.kms_key_id,
                                    "tags": secret.tags,
                                    "default_version_id": secret.default_version_id,
                                    "versions": secret.versions,
                                    "version_stages": secret.version_stages,
                                    "last_changed_date": secret.last_changed_date,
                                    "created_date": secret.created_date,
                                    "deleted_date": secret.deleted_date,
                                    "resource_policy": getattr(
                                        secret, "resource_policy", None
                                    ),
                                }
                        state_to_save[account_id][region_name] = secrets_data

            # Save to disk using pickle
            save_file = self.data_dir / "secretsmanager_state.pkl"
            LOG.info(f"Saving SecretsManager state to {save_file}")
            with open(save_file, "wb") as f:
                pickle.dump(state_to_save, f)
            LOG.info(
                f"Successfully saved {sum(len(regions) for regions in state_to_save.values())} "
                f"region(s) of secrets"
            )

        except Exception as e:
            LOG.error(f"Failed to save SecretsManager state: {e}", exc_info=True)


class SecretsManagerLoadVisitor(StateVisitor):
    """Visitor that loads SecretsManager state from disk."""

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)

    def visit(self, state_container: Any):
        """Load the SecretsManager backend state."""
        if isinstance(state_container, BackendDict):
            self._load_backend_dict(state_container)

    def _load_backend_dict(self, backend_dict: BackendDict):
        """Load the moto SecretsManager backend dict from disk."""
        try:
            save_file = self.data_dir / "secretsmanager_state.pkl"

            if not save_file.exists():
                LOG.warning(f"No persisted SecretsManager state found at {save_file}")
                # List directory contents for debugging
                if self.data_dir.exists():
                    LOG.debug(
                        f"Contents of {self.data_dir}: {list(self.data_dir.iterdir())}"
                    )
                return

            LOG.info(f"Loading SecretsManager state from {save_file}")

            with open(save_file, "rb") as f:
                state_to_load = pickle.load(f)

            LOG.info(f"Loaded state contains {len(state_to_load)} account(s)")

            # Restore the state to the backend
            for account_id, regions in state_to_load.items():
                if account_id not in backend_dict:
                    backend_dict[account_id] = {}

                for region_name, secrets_data in regions.items():
                    LOG.debug(
                        f"Loading {len(secrets_data)} secret(s) for "
                        f"account {account_id}, region {region_name}"
                    )

                    # Get or create the backend for this account/region
                    if region_name not in backend_dict[account_id]:
                        backend_dict[account_id][region_name] = SecretsManagerBackend(
                            region_name, account_id
                        )

                    backend = backend_dict[account_id][region_name]

                    # Restore each secret
                    for secret_id, secret_data in secrets_data.items():
                        try:
                            # Create the secret object
                            # FakeSecret expects positional args: region_name, secret_id,
                            # secret_string, secret_binary, description, tags, kms_key_id,
                            # secret_version, version_id
                            # Use the name as secret_id if secret_id is not available
                            stored_secret_id = (
                                secret_data.get("secret_id")
                                or secret_data.get("name")
                                or secret_id
                            )

                            secret = FakeSecret(
                                region_name,  # region_name (positional)
                                stored_secret_id,  # secret_id (positional)
                                None,  # secret_string - will be set via versions
                                None,  # secret_binary - will be set via versions
                                secret_data.get("description") or "",  # description
                                secret_data.get("tags") or [],  # tags
                                secret_data.get("kms_key_id") or None,  # kms_key_id
                                None,  # secret_version
                                secret_data.get("default_version_id") or None,  # version_id
                            )

                            # Set the name and account_id attributes directly
                            secret.name = secret_data.get("name") or stored_secret_id
                            secret.account_id = account_id

                            # Restore metadata
                            secret.versions = secret_data.get("versions", {})
                            secret.version_stages = secret_data.get("version_stages", {})
                            secret.default_version_id = secret_data.get(
                                "default_version_id"
                            )
                            secret.last_changed_date = secret_data.get(
                                "last_changed_date"
                            )
                            secret.created_date = secret_data.get("created_date")
                            secret.deleted_date = secret_data.get("deleted_date")

                            # Restore resource policy if it exists
                            if secret_data.get("resource_policy"):
                                secret.resource_policy = secret_data["resource_policy"]

                            # Add to backend
                            backend.secrets[secret_id] = secret
                            LOG.debug(
                                f"Restored secret {secret_id} to backend. "
                                f"Backend now has {len(backend.secrets)} secret(s)"
                            )

                        except Exception as e:
                            LOG.warning(f"Failed to restore secret {secret_id}: {e}")

            # Verify the restoration
            total_secrets = 0
            for account_id, regions in backend_dict.items():
                for region_name, backend in regions.items():
                    if isinstance(backend, SecretsManagerBackend):
                        count = len(backend.secrets)
                        total_secrets += count
                        LOG.debug(
                            f"After load: account {account_id}, region {region_name} "
                            f"has {count} secret(s)"
                        )

            LOG.info(
                f"Successfully loaded {sum(len(regions) for regions in state_to_load.values())} "
                f"region(s) of secrets, total secrets: {total_secrets}"
            )

        except Exception as e:
            LOG.error(f"Failed to load SecretsManager state: {e}", exc_info=True)


def get_secretsmanager_data_dir() -> Path:
    """Get the data directory for SecretsManager persistence."""
    # Use the same path structure that LocalStack uses for state
    # The log shows: /var/lib/localstack/state/secretsmanager/
    data_dir = Path(config.dirs.data) / "secretsmanager"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def save_secretsmanager_state():
    """Save the current SecretsManager state to disk."""
    if not config.is_persistence_enabled():
        return

    try:
        LOG.debug(
            f"Saving SecretsManager state... Backend dict id: {id(secretsmanager_backends)}"
        )
        visitor = SecretsManagerSaveVisitor(str(get_secretsmanager_data_dir()))
        # Always use the current global backend from moto
        from moto.secretsmanager import secretsmanager_backends as current_backends

        visitor.visit(current_backends)
    except Exception as e:
        LOG.error(f"Error saving SecretsManager state: {e}", exc_info=True)


def load_secretsmanager_state():
    """Load the SecretsManager state from disk."""
    if not config.is_persistence_enabled():
        LOG.debug("Persistence is not enabled, skipping load")
        return

    try:
        data_dir = get_secretsmanager_data_dir()
        LOG.info(
            f"Loading SecretsManager state from {data_dir}, "
            f"Backend dict id: {id(secretsmanager_backends)}"
        )
        visitor = SecretsManagerLoadVisitor(str(data_dir))
        # Always use the current global backend from moto
        from moto.secretsmanager import secretsmanager_backends as current_backends

        visitor.visit(current_backends)
    except Exception as e:
        LOG.error(f"Error loading SecretsManager state: {e}", exc_info=True)


# Note: Hooks are not used here - the provider's lifecycle methods handle persistence
# The provider's on_after_init() loads state and on_before_stop() saves state