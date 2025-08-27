"""Factory for encoders and decoders"""

from localstack import config
from localstack.state import Decoder, Encoder
from localstack.state.pickle import PickleDecoder, PickleEncoder

ENCODERS = {
    "dill": PickleEncoder,
}
"""Encoders that map to the name of ``STATE_SERIALIZATION_BACKEND``."""

DECODERS = {
    "dill": PickleDecoder,
}
"""Decoders that map to the name of ``STATE_SERIALIZATION_BACKEND``."""


def create_encoder(encoder_type: str) -> Encoder:
    cls = ENCODERS.get(encoder_type)
    if cls is None:
        raise ValueError(f"Unknown encoder type: {encoder_type}")
    return cls()


def create_decoder(decoder_type: str) -> Decoder:
    cls = DECODERS.get(decoder_type, PickleDecoder)
    if cls is None:
        raise ValueError(f"Unknown decoder type: {decoder_type}")
    return cls()


def get_default_encoder() -> Encoder:
    """
    Gets the default encoder based on the state serialization backend defined in the configuration
    ``STATE_SERIALIZATION_BACKEND``.

    If the serialization backend specified in the configuration leads to an error
    (such as an invalid backend), a ``PickleEncoder`` is returned as a fallback.

    :return: The default encoder for state serialization.
    """
    try:
        return create_encoder(config.STATE_SERIALIZATION_BACKEND)
    except ValueError:
        return PickleEncoder()


def get_default_decoder() -> Decoder:
    """
    Gets the default decoder based on the state serialization backend defined in the configuration
    ``STATE_SERIALIZATION_BACKEND``.

    If the serialization backend specified in the configuration leads to an error
    (such as an invalid backend), a ``PickleDecoder`` is returned as a fallback.

    :return: The default decoder for state serialization.
    """
    try:
        return create_decoder(config.STATE_SERIALIZATION_BACKEND)
    except ValueError:
        return PickleDecoder()
