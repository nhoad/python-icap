from examples import withoutmypants
from icap.parsing import HTTPMessageParser


def test_withoutmypants_modified():
    request = HTTPMessageParser.from_bytes("GET http://google.com/?q=foo HTTP/1.1\r\n\r\n")
    withoutmypants.reqmod(request)
    print str(request)
    assert "?q=foo+without+my+pants" in str(request)

def test_withoutmypants_not_modified():
    request = HTTPMessageParser.from_bytes("GET http://google.com/?qq=foo HTTP/1.1\r\n\r\n")
    withoutmypants.reqmod(request)
    print str(request)
    assert "without+my+pants" not in str(request)
