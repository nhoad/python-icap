import urllib2

from examples import withoutmypants
from icap.parsing import HTTPMessageParser


def test_withoutmypants():
    request = HTTPMessageParser.from_bytes("GET http://google.com/?q=foo HTTP/1.1\r\n\r\n")
    withoutmypants.reqmod(request)

    print str(request)

    assert "?q=foo+without+my+pants" in str(request)
