from scanner import SimpleScanner, Logger

def test_simple_scanner_instantiation():
    logger = Logger(":memory:")
    scanner = SimpleScanner("http://example.com", logger, max_pages=1)
    assert scanner.base_url.startswith("http")
    assert scanner.logger is logger
