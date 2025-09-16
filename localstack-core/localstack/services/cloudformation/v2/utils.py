from localstack import config


def is_v2_engine() -> bool:
    return config.SERVICE_PROVIDER_CONFIG.get_provider("cloudformation") not in {
        "engine-legacy",
        "engine-legacy_pro",
    }
