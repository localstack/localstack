def get_hash_algorithm(signing_algorithm: str) -> str:
    """
    Return the hashing algorithm for a given signing algorithm.
    eg. "RSASSA_PSS_SHA_512" -> "SHA_512"
    """
    return "_".join(signing_algorithm.rsplit(sep="_", maxsplit=-2)[-2:])
