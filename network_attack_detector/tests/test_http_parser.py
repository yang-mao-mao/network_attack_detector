from src.parser.http_parser import HttpParser


def test_http_parser_decodes_query():
    parsed = HttpParser().parse(
        "GET /search?q=union%20select HTTP/1.1\r\nHost: demo.local\r\n\r\n"
    )
    assert parsed is not None
    assert parsed.method == "GET"
    assert parsed.query == "q=union select"

