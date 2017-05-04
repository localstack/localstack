"""Utilities for writing code that runs on Python 2 and 3"""


from six import binary_type, text_type


def text_(s, encoding='utf-8', errors='strict'):
    """If ``s`` is an instance of ``binary_type``, return
    ``s.decode(encoding, errors)``, otherwise return ``s``
    """
    return s.decode(encoding, errors) if isinstance(s, binary_type) else s


def bytes_(s, encoding='utf-8', errors='strict'):
    """ If ``s`` is an instance of ``text_type``, return
    ``s.encode(encoding, errors)``, otherwise return ``s``
    """
    return s.encode(encoding, errors) if isinstance(s, text_type) else s
