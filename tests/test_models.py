from icap import ICAPRequest, ICAPResponse, RequestLine, HeadersDict, HTTPRequest, HTTPResponse, StatusLine
from icap.errors import ICAPAbort
from icap.models import ICAPMessage, HTTPMessage


class TestHTTPMessage(object):
    def test_is_response_and_is_response(self):
        m = HTTPMessage()
        assert not (m.is_request or m.is_response)

        m = HTTPRequest()
        assert m.is_request
        assert not m.is_response

        m = HTTPResponse()
        assert not m.is_request
        assert m.is_response

    def test_body_setter(self):
        m = HTTPMessage()

        m.body = b'foo'
        assert m.body[0].content == b'foo'

        m.body = [b'foo', b'bar', b'baz']
        assert [b.content for b in m.body] == [b'foo', b'bar', b'baz']

        m.body = (b'foo', b'bar', b'baz')
        assert [b.content for b in m.body] == [b'foo', b'bar', b'baz']

        try:
            m.body = 1
        except TypeError:
            pass
        else:
            assert False, "invalid body type should throw error"

        try:
            m.body = 'non-bytestring'
        except TypeError:
            pass
        else:
            assert False, "invalid body type should throw error"


class TestICAPMessage(object):
    def test_is_response_and_is_response(self):
        m = ICAPMessage()
        assert not (m.is_request or m.is_response)

        m = ICAPRequest()
        assert m.is_request
        assert not m.is_response

        m = ICAPResponse()
        assert not m.is_request
        assert m.is_response

    def test_has_body(self):
        r = self.request('OPTIONS')
        assert not r.has_body

        r = self.request('OPTIONS')
        r.headers['Encapsulated'] = 'null-body=0'
        assert not r.has_body

        r = self.request('REQMOD')
        r.headers['Encapsulated'] = 'req-body=0'
        assert r.has_body

        r = self.request('RESPMOD')
        r.headers['Encapsulated'] = 'resp-body=0'
        assert r.has_body

    def request(self, method, *args, **kwargs):
        return ICAPRequest(RequestLine(method, '/', 'ICAP/1.0'), *args, **kwargs)


class TestICAPRequest(object):
    def test_allow_204(self):
        request = self.request('REQMOD')
        assert not request.allow_204

        request = self.request('REQMOD', headers=HeadersDict([('Allow', '204')]))
        assert request.allow_204

    def test_init_defaults(self):
        d = ICAPRequest()
        assert bytes(d.request_line) == b'UNKNOWN / ICAP/1.0'

    def test_is_reqmod(self):
        assert self.request('REQMOD').is_reqmod
        assert not self.request('RESPMOD').is_reqmod

    def test_is_respmod(self):
        assert self.request('RESPMOD').is_respmod
        assert not self.request('REQMOD').is_respmod

    def test_is_options(self):
        assert not self.request('REQMOD').is_options
        assert not self.request('RESPMOD').is_options
        assert self.request('OPTIONS').is_options

    def request(self, method, *args, **kwargs):
        return ICAPRequest(RequestLine(method, '/', 'ICAP/1.0'), *args, **kwargs)


class TestICAPResponse(object):
    def test_from_error(self):
        s = ICAPResponse.from_error(200)
        assert bytes(s) == b'ICAP/1.0 200 OK\r\n'

        s = ICAPResponse.from_error(ICAPAbort(200))
        assert bytes(s) == b'ICAP/1.0 200 OK\r\n'

        s = ICAPResponse.from_error(ICAPAbort(204))
        assert bytes(s) == b'ICAP/1.0 204 No Modifications Needed\r\n'

        headers = HeadersDict([
            ('header', 'value'),
        ])

        s = ICAPResponse.from_error(ICAPAbort(204))
        s.headers = headers
        assert bytes(s) == b'ICAP/1.0 204 No Modifications Needed\r\nheader: value\r\n'


def test_StatusLine_defaults():
    s = StatusLine('HTTP/1.1', 200)
    assert s.reason == 'OK'

    s = StatusLine('ICAP/1.1', 204)
    assert s.reason == 'No Modifications Needed'
