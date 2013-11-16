from examples import withoutmypants
from icap.parsing import HTTPMessageParser


def test_withoutmypants_modified():
    request = HTTPMessageParser.from_bytes(b"GET http://google.com/?q=foo HTTP/1.1\r\n\r\n")
    withoutmypants.reqmod(request)
    print(str(request))
    assert b"?q=foo+without+my+pants" in bytes(request)

def test_withoutmypants_not_modified():
    request = HTTPMessageParser.from_bytes(b"GET http://google.com/?qq=foo HTTP/1.1\r\n\r\n")
    withoutmypants.reqmod(request)
    print(str(request))
    assert b"without+my+pants" not in bytes(request)
