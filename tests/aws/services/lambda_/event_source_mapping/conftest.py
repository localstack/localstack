import pytest
from localstack_snapshot.snapshots import SnapshotSession
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer_utility import (
    SNAPSHOT_BASIC_TRANSFORMER_NEW,
    TransformerUtility,
)
from localstack.utils.aws.arns import get_partition
from tests.aws.services.lambda_.event_source_mapping.utils import (
    is_old_esm,
)

# Only match EventSourceMappingArn field if ESM v2+
pytestmark = markers.snapshot.skip_snapshot_verify(
    condition=is_old_esm,
    paths=["$..EventSourceMappingArn"],
)


# Here, we overwrite the snapshot fixture to allow the event_source_mapping subdir
# to use the newer basic transformer.
@pytest.fixture(scope="function")
def snapshot(request, _snapshot_session: SnapshotSession, account_id, region_name):
    _snapshot_session.transform = TransformerUtility

    _snapshot_session.add_transformer(RegexTransformer(account_id, "1" * 12), priority=2)
    _snapshot_session.add_transformer(RegexTransformer(region_name, "<region>"), priority=2)
    _snapshot_session.add_transformer(
        RegexTransformer(f"arn:{get_partition(region_name)}:", "arn:<partition>:"), priority=2
    )

    _snapshot_session.add_transformer(SNAPSHOT_BASIC_TRANSFORMER_NEW, priority=0)

    return _snapshot_session
