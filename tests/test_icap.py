import pytest

from icap import ICAPRequest, ICAPResponse, HeadersDict, RequestLine, StatusLine
from icap.models import HTTPMessage
from icap.parsing import HTTPMessageParser, ICAPRequestParser
from icap.errors import MalformedRequestError, InvalidEncapsulatedHeadersError, ICAPAbort


def data_string(path):
    return open('data/' + path, 'rb').read()


def assert_bodies_match(
        message, expected_body):

    assert isinstance(message, (ICAPRequest, ICAPResponse, HTTPMessage))

    if isinstance(message, ICAPRequest):
        body = message.http.body
    else:
        body = message.body_bytes

    assert isinstance(expected_body, bytes)
    assert isinstance(body, bytes)
    assert body == expected_body


@pytest.mark.parametrize(('input_bytes', 'expected_body'), [
    (b'GET / HTTP/1.1\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n',
        b'Wikipedia in\r\n\r\nchunks.'),
    (b'GET / HTTP/1.1\r\n\r\n4;bar\r\nWiki\r\n5;foo\r\npedia\r\nE;qwer\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n',
        b'Wikipedia in\r\n\r\nchunks.'),
    (b'GET / HTTP/1.1\r\n\r\n4;bar\r\nWiki\r\n5;foo\r\npedia\r\nE;qwer\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n',
        b'Wikipedia in\r\n\r\nchunks.'),
])
def test_chunked_messages(input_bytes, expected_body):
    m = HTTPMessageParser.from_bytes(input_bytes)

    assert_bodies_match(m, expected_body)


def test_multiline_headers():
    s = (
        b'OPTIONS / ICAP/1.0\r\n'
        b'Great-header: foo \r\n'
        b'\t       bar\r\n'
        b'\r\n'
    )
    m = ICAPRequestParser.from_bytes(s)
    assert m.headers['great-header'] == 'foo bar'


@pytest.mark.parametrize(('input_bytes', 'expected_headers', 'expected_sline'), [
    (
        b'GET / HTTP/1.1\r\nen-US Content-Type: text/xml\r\n\r\n0\r\n\r\n',
        HeadersDict([('en-US Content-Type', 'text/xml')]),
        b'GET / HTTP/1.1',
    ),
    (
        'HTTP/1.1 500 Oriëntatieprobleem\r\n\r\n0\r\n\r\n'.encode('utf8'),
        HeadersDict(),
        'HTTP/1.1 500 Oriëntatieprobleem'.encode('utf8'),
    ),
    (
        b'GET / HTTP/1.1\r\nFoo: \r\n\r\n0\r\n\r\n',
        HeadersDict([('Foo', '')]),
        b'GET / HTTP/1.1',
    ),
    (
        b'GET / HTTP/1.1\r\nFoo: \r\n\r\n0    \r\n\r\n',
        HeadersDict([('Foo', '')]),
        b'GET / HTTP/1.1',
    ),
    (
        b'GET / HTTP/1.1\r\nFoo: \r\n\r\n000\r\n\r\n',
        HeadersDict([('Foo', '')]),
        b'GET / HTTP/1.1',
    ),
    (
        b"GET / HTTP/1.1\r\nLine1: abc\r\n\tdef\r\n ghi\r\n\t\tjkl\r\n  mno \r\n\t \tqrs\r\nLine2: \t line2\t\r\n\r\n",
        HeadersDict([
            ('Line1', 'abcdefghijklmno qrs'),
            ('Line2', 'line2\t'),
        ]),
        b"GET / HTTP/1.1",
    ),
    (
        b'CONNECT home_0.netscape.com:443 HTTP/1.0\r\nFoo: \r\n\r\n0\r\n\r\n',
        HeadersDict([('Foo', '')]),
        b'CONNECT home_0.netscape.com:443 HTTP/1.0',
    ),
    # FIXME: trailing-headers
    #(
    #    b"POST /chunked_w_trailing_headers HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\nVary: *\r\nContent-Type: text/plain\r\n\r\n",
    #    HeadersDict([('Transfer-Encoding', 'chunked')]),
    #    b"POST /chunked_w_trailing_headers HTTP/1.1",
    #),
    # FIXME: http-0.9
    #(
    #    b"GET /\r\n\r\n0\r\n\r\n",
    #    HeadersDict(),
    #    b'GET /',
    #),
    # FIXME: non-crlf-endings
    #(
    #    b'GET / HTTP/1.1\nFoo: \nBar: baz\n0\n\n',
    #    HeadersDict([
    #        ('Foo', ''),
    #        ('Bar', 'baz'),
    #    ]),
    #    b'GET / HTTP/1.1',
    #),
])
def test_horrible_http_parsing(input_bytes, expected_headers, expected_sline):
    m = HTTPMessageParser.from_bytes(input_bytes)

    print(bytes(m.headers))
    print(bytes(expected_headers))
    assert m.headers == expected_headers

    if m.is_request:
        assert bytes(m.request_line) == expected_sline
    elif m.is_response:
        assert bytes(m.status_line) == expected_sline
    else:
        assert False, "Not a request or response!"


def test_icap_parsing_simple():
    expected = data_string('request_with_http_response_and_payload.request')

    m = ICAPRequestParser.from_bytes(expected)

    assert isinstance(m, ICAPRequest)

    print('-----')
    print(expected)
    print('-----')
    print('parent headers', m.headers)
    print('child headers', m.http.headers)
    assert_bodies_match(m, b'this is a payload')


def test_icap_parsing_complex():
    'Tests req-hdr, res-hdr, res-body'

    expected = data_string('icap_request_with_two_header_sets.request')
    expected_headers = HeadersDict([
        ('Host', 'icap.example.org'),
        ('Encapsulated', 'req-hdr=0, res-hdr=137, res-body=296'),
    ])

    expected_child_request_headers = HeadersDict([
        ('Host', 'www.origin-server.com'),
        ('Accept', 'text/html, text/plain, image/gif'),
        ('Accept-Encoding', 'gzip, compress'),
    ])

    expected_child_headers = HeadersDict([
        ('Date', 'Mon, 10 Jan 2000 09:52:22 GMT'),
        ('Server', 'Apache/1.3.6 (Unix)'),
        ('ETag', '"63840-1ab7-378d415b"'),
        ('Content-Type', 'text/html'),
        ('Content-Length', '51'),
    ])

    m = ICAPRequestParser.from_bytes(expected)

    assert isinstance(m, ICAPRequest)

    child = m.http

    assert bytes(m.request_line) == b'RESPMOD icap://icap.example.org/respmod ICAP/1.0'
    assert bytes(child.request_line) == b'GET /origin-resource HTTP/1.1'
    assert bytes(child.status_line) == b'HTTP/1.1 200 OK'

    assert m.headers == expected_headers
    assert child.request_headers == expected_child_request_headers
    assert child.headers == expected_child_headers

    assert_bodies_match(m, b'This is data that was returned by an origin server.')


@pytest.mark.parametrize(('test_file', 'expected_values'), [
    ('icap_reqbody.response', dict(body='This is data that was returned by an origin server.')),
    ('icap_reqhdr_resbody.response', dict(req_parts=True, body=['This is data that was returned by an origin server.'])),
    ('icap_resbody.response', dict(body=['This is data that was returned by an origin server.'])),
    ('icap_nullbody.response', dict()),
])
def test_icap_parsing_stupid(test_file, expected_values):
    '''Test for the stupidest combinations of Encapsulated headers that I can come up with.'''
    data = data_string(test_file)

    print(test_file)
    print('----')
    print(data)
    print('----')

    try:
        ICAPRequestParser.from_bytes(data)
    except ICAPAbort as e:
        assert e.status_code == 418


@pytest.mark.parametrize(('input_bytes', 'expected_request'), [
    (b'GET / HTTP/1.1\r\n\r\n', True),
    (b'HTTP/1.1 200 OK\r\n\r\n', False),
    (b'RESPMOD / ICAP/1.1\r\n\r\n', True),
    (b'ICAP/1.1 200 OK\r\n\r\n', False),
])
def test_sline_matching(input_bytes, expected_request):
    m = HTTPMessageParser.from_bytes(input_bytes)

    if expected_request:
        m.request_line
        assert m.is_request
        assert not m.is_response
        assert isinstance(m.request_line, RequestLine)
    else:
        m.status_line
        assert m.is_response
        assert not m.is_request
        assert isinstance(m.status_line, StatusLine)


@pytest.mark.parametrize(('input_bytes', 'expected_fail'), [
    (b'RESPMOD / ICAP/1.1\r\n\r\n', True),
    (b'REQMOD / ICAP/1.1\r\n\r\n', True),
    (b'OPTIONS / ICAP/1.1\r\n\r\n', False),
])
def test_encapsulated_header_requirement(input_bytes, expected_fail):
    try:
        m = ICAPRequestParser.from_bytes(input_bytes)
    except InvalidEncapsulatedHeadersError as e:
        if not expected_fail:
            raise e  # pragma: no cover
    else:
        if expected_fail:  # pragma: no cover
            assert False, "Did not raise an error"


def test_short_read_http_headers():
    input_bytes = b'GET / HTTP/1.1\r\nHea'
    try:
        HTTPMessageParser.from_bytes(input_bytes)
    except MalformedRequestError:
        pass
    else:  # pragma: no cover
        assert False


def test_short_read_icap_headers():
    input_bytes = b'REQMOD / ICAP/1.1\r\nHea'
    try:
        ICAPRequestParser.from_bytes(input_bytes)
    except MalformedRequestError:
        pass
    else:  # pragma: no cover
        assert False


@pytest.mark.parametrize(('input_bytes'), [
    b'GET / \r\n',
    b'HTTP/1.1 200 \r\n',
    b'HTTP/1.1 20g0 OK\r\n',
    b'RESPMOD / \r\n',
    b'ICAP/1.1 OK\r\n\r\n',
])
def test_malformed_request_line(input_bytes):
    try:
        HTTPMessageParser.from_bytes(input_bytes)
    except MalformedRequestError:
        pass
    else:
        assert False, "Request is malformed, exception not raised."  # pragma: no cover
