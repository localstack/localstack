from localstack.logging.format import compress_logger_name


def test_compress_logger_name():
    assert compress_logger_name("log", 1) == "l"
    assert compress_logger_name("log", 2) == "lo"
    assert compress_logger_name("log", 3) == "log"
    assert compress_logger_name("log", 5) == "log"
    assert compress_logger_name("my.very.long.logger.name", 1) == "m.v.l.l.n"
    assert compress_logger_name("my.very.long.logger.name", 11) == "m.v.l.l.nam"
    assert compress_logger_name("my.very.long.logger.name", 12) == "m.v.l.l.name"
    assert compress_logger_name("my.very.long.logger.name", 16) == "m.v.l.l.name"
    assert compress_logger_name("my.very.long.logger.name", 17) == "m.v.l.logger.name"
    assert compress_logger_name("my.very.long.logger.name", 24) == "my.very.long.logger.name"
