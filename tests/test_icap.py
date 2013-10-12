import pytest

from icap import ChunkedMessage, ICAPRequest, ICAPResponse, HeadersDict, RequestLine, StatusLine
from icap.errors import MalformedRequestError, InvalidEncapsulatedHeadersError, ICAPAbort

def data_string(req_line, path):
    parts = req_line, open('data/' + path).read()
    return '\r\n'.join(p for p in parts if p)


def assert_stream_consumed(message):
    assert message.stream.read() == ''


def assert_bodies_match(
        message, expected_bodies, headers=None, total_length=None):

    chunks = list(message)
    if isinstance(expected_bodies, basestring):
        expected_bodies = [expected_bodies]

    assert [b.content for b in chunks] == expected_bodies

    if total_length:
        assert total_length == len(''.join(b.content for b in chunks))

    if headers:
        assert len(chunks) == len(headers)
        for chunk, header in zip(chunks, headers):
            assert chunk.header == header


@pytest.mark.parametrize(('input_bytes', 'expected_values'), [
    ('GET / HTTP/1.1\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n',
        dict(values=['Wiki', 'pedia', ' in\r\n\r\nchunks.'])),
    ('GET / HTTP/1.1\r\n\r\n4;bar\r\nWiki\r\n5;foo\r\npedia\r\nE;qwer\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n',
        dict(values=['Wiki', 'pedia', ' in\r\n\r\nchunks.'], headers=['bar', 'foo', 'qwer'])),
    ('GET / HTTP/1.1\r\n\r\n4;bar\r\nWiki\r\n5;foo\r\npedia\r\nE;qwer\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n',
        dict(values=['Wiki', 'pedia', ' in\r\n\r\nchunks.'], headers=['bar', 'foo', 'qwer'])),
])
def test_chunked_messages(input_bytes, expected_values):
    m = ChunkedMessage.from_bytes(input_bytes)

    assert_bodies_match(
        m, expected_values.get('values'),
        headers=expected_values.get('headers'), total_length=23)
    assert_stream_consumed(m)


def test_multiline_headers():
    s = (
        'GET / HTTP/1.1\r\n'
        'Great-header: foo\r\n'
        '\t       bar\r\n'
        '\r\n'
    )
    m = ChunkedMessage.from_bytes(s)
    assert m.headers['great-header'] == 'foo bar'


def test_icap_parsing_simple():
    expected = data_string('', 'icap_response_with_payload.response')

    m = ICAPRequest.from_bytes(expected)

    assert isinstance(m, ICAPRequest)

    print '-----'
    print expected
    print '-----'
    print 'parent headers', m.headers
    print 'child headers', m.encapsulated_message.headers
    assert_bodies_match(m, 'This is data that was returned by an origin server, but with\r\nvalue added by an ICAP server.')
    assert_stream_consumed(m)


def test_icap_parsing_complex():
    'Tests req-hdr, res-hdr, res-body'

    expected = data_string('', 'icap_request_with_two_header_sets.request')
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

    m = ICAPRequest.from_bytes(expected)

    assert isinstance(m, ICAPRequest)

    child = m.encapsulated_message

    assert ' '.join(m.sline) == 'RESPMOD icap://icap.example.org/satisf ICAP/1.0'
    assert ' '.join(child.request_sline) == 'GET /origin-resource HTTP/1.1'
    assert ' '.join(map(str, child.sline)) == 'HTTP/1.1 200 OK'

    assert m.headers == expected_headers
    assert child.request_headers == expected_child_request_headers
    assert child.headers == expected_child_headers

    assert_bodies_match(m, 'This is data that was returned by an origin server.')
    assert_stream_consumed(m)


@pytest.mark.parametrize(('test_file', 'expected_values'), [
    ('icap_reqbody.response', dict(body='This is data that was returned by an origin server.')),
    ('icap_reqhdr_resbody.response', dict(req_parts=True, body=['This is data that was returned by an origin server.'])),
    ('icap_resbody.response', dict(body=['This is data that was returned by an origin server.'])),
    ('icap_nullbody.response', dict()),
])
def test_icap_parsing_stupid(test_file, expected_values):
    '''Test for the stupidest combinations of Encapsulated headers that I can come up with.'''
    data = data_string('', test_file)

    print test_file
    print '----'
    print data
    print '----'

    m = ICAPRequest.from_bytes(data)
    child = m.encapsulated_message

    has_headers = expected_values.get('headers', False)
    has_req_parts = expected_values.get('req_parts', False)
    body = expected_values.get('body')

    if has_req_parts:
        assert m.is_respmod
        assert child.request_sline
        assert child.request_headers

    assert bool(child.headers) == has_headers

    if body:
        assert_bodies_match(m, body)
    else:
        assert_bodies_match(m, [])

    assert_stream_consumed(m)


@pytest.mark.parametrize(('input_bytes', 'expected_request'), [
    ('GET / HTTP/1.1\r\n\r\n', True),
    ('HTTP/1.1 200 OK\r\n\r\n', False),
    ('RESPMOD / ICAP/1.1\r\n\r\n', True),
    ('ICAP/1.1 200 OK\r\n\r\n', False),
])
def test_sline_matching(input_bytes, expected_request):
    m = ChunkedMessage.from_bytes(input_bytes)

    assert m.headers_complete()

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
    assert_stream_consumed(m)


@pytest.mark.parametrize(('input_bytes', 'expected_fail'), [
    ('RESPMOD / ICAP/1.1\r\nEncapsulated: null-body=0\r\n\r\n', False),
    ('REQMOD / ICAP/1.1\r\nEncapsulated: null-body=0\r\n\r\n', False),
    ('OPTIONS / ICAP/1.1\r\nEncapsulated: null-body=0\r\n\r\n', False),
    ('OPTIONS / ICAP/1.1\r\n\r\n', False),
])
def test_encapsulated_header_requirement(input_bytes, expected_fail):
    m = ICAPRequest.from_bytes(input_bytes)
    try:
        m.encapsulated_header
    except InvalidEncapsulatedHeadersError:
        if not expected_fail:
            raise
    else:
        if expected_fail:
            assert False, "Did not raise an error"


def test_short_read_headers():
    input_bytes = 'GET / HTTP/1.1\r\nHea'
    m = ChunkedMessage.from_bytes(input_bytes)
    assert m is None


@pytest.mark.parametrize(('input_bytes'), [
    'GET / \r\n',
    'HTTP/1.1 200 \r\n',
    'HTTP/1.1 20g0 OK\r\n',
    'RESPMOD / \r\n',
    'ICAP/1.1 OK\r\n\r\n',
])
def test_malformed_request_line(input_bytes):
    try:
        ChunkedMessage.from_bytes(input_bytes)
    except MalformedRequestError:
        pass
    else:
        assert False, "Request is malformed, exception not raised."

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

    for i in xrange(6):
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

    assert a == b
    assert a != c
    assert c != d

    assert str(a) == '\r\n'.join(['Foo: bar']*6) + '\r\n'
    assert str(c) == 'lamp: i love lamp\r\n'
    assert str(d) == 'lamp: i dont love lamp\r\n'
    assert str(HeadersDict()) == ''


class TestICAPResponse(object):
    def test_from_error(self):
        s = ICAPResponse.from_error(ICAPAbort(200))
        assert str(s) == 'ICAP/1.0 200 OK\r\n'

        s = ICAPResponse.from_error(ICAPAbort(204))
        assert str(s) == 'ICAP/1.0 204 No modifications needed\r\n'

        headers = HeadersDict([
            ('header', 'value'),
        ])

        s = ICAPResponse.from_error(ICAPAbort(204))
        s.headers = headers
        assert str(s) == 'ICAP/1.0 204 No modifications needed\r\nheader: value\r\n'
