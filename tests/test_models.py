import pytest

from icap import ICAPRequest, ICAPResponse, RequestLine, HeadersDict, HTTPRequest, HTTPResponse, StatusLine
from icap.errors import ICAPAbort
from icap.models import ICAPMessage, HTTPMessage


class TestHTTPMessage(object):
    def test_is_request_and_is_response(self):
        m = HTTPMessage()
        assert not (m.is_request or m.is_response)

        m = HTTPRequest()
        assert m.is_request
        assert not m.is_response

        m = HTTPResponse()
        assert not m.is_request
        assert m.is_response

    @pytest.mark.parametrize('cls', [
        HTTPRequest,
        HTTPResponse,
    ])
    def test_default_attributes(self, cls):
        m = cls()

        assert m.request_line == RequestLine('GET', '/', 'HTTP/1.1')
        assert m.headers == HeadersDict()

        if cls == HTTPResponse:
            assert m.request_headers == HeadersDict()
            assert m.status_line == StatusLine('HTTP/1.1', 200, 'OK')

    def test_body_setter(self):
        m = HTTPMessage()

        m.body = b'foo'
        assert m.body_bytes == b'foo'

        try:
            m.body = 1
        except TypeError:
            pass
        else:
            assert False, "invalid body type should throw error"

        m.body = 'non-bytestring'

        m.headers['Content-Type'] = 'text/plain'

        try:
            m.body = 'non-bytestring'
        except TypeError:
            pass
        else:
            assert False, "Content-Type with no charset should raise TypeError"

        m.headers.replace('Content-Type', 'image/png')

        try:
            m.body = 'non-bytestring'
        except TypeError:
            pass
        else:
            assert False, "Content-Type with no charset should raise TypeError"


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


def test_HeadersDict():
    h = HeadersDict()
    h['Foo'] = 'bar'
    h['Foo'] = 'baz'

    assert h['foo'] == 'bar'
    assert h['FOO'] == 'bar'
    assert h.get('foo') == 'bar'
    assert h.get('bar') is None
    assert h.get('baz', 'asdf') == 'asdf'
    assert h.getlist('foo') == ['bar', 'baz']
    assert h.getlist('bar') == []

    h.replace('Foo', 'bar')
    assert h.getlist('Foo') == ['bar']

    b = HeadersDict()

    for i in range(6):
        b['Foo'] = 'bar'

    a = HeadersDict([
        ('Foo', 'bar'),
        ('Foo', 'bar'),
        ('Foo', 'bar'),
        ('Foo', 'bar'),
        ('Foo', 'bar'),
        ('Foo', 'bar'),
    ])

    c = HeadersDict([
        ('lamp', 'i love lamp'),
    ])

    d = HeadersDict([
        ('lamp', 'i dont love lamp'),
    ])

    assert 'LAMP' in d
    assert 'LaMp' in d
    assert 'lamp' in d

    assert a == b
    assert a != c
    assert c != d

    assert bytes(a) == '\r\n'.join(['Foo: bar']*6).encode('utf8') + b'\r\n'
    assert bytes(c) == b'lamp: i love lamp\r\n'
    assert bytes(d) == b'lamp: i dont love lamp\r\n'
    assert bytes(HeadersDict()) == b''

    e = HeadersDict()

    e['foo'] = b'bar'
    e[b'bar'] = 'baz'
    try:
        b[1] = 'bar'
    except TypeError:
        pass
    else:
        assert False, "non-str key should raise TypeError"
    try:
        b['baz'] = 1
    except TypeError:
        pass
    else:
        assert False, "non-str value should raise TypeError"

    assert e['foo'] == 'bar'
    assert e[b'bar'] == 'baz'
    assert b'bar' in e
