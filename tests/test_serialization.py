import pytest

from mock import MagicMock, call

from icap import ICAPResponse, HTTPResponse, HeadersDict
from icap.serialization import (
    Serializer, response_headers, options_response_headers,
    remove_invalid_headers)


class TestSerializer(object):
    def test_serialize_options_to_stream(self):
        s = ICAPResponse.from_error(200)
        s.is_options = True

        stream = MagicMock()
        Serializer(s, 'asdf', is_options=True).serialize_to_stream(stream)

        calls = stream.mock_calls

        print(calls)
        assert calls[-1] == call.write(b'\r\n')

    def test_serialize_no_body_to_stream(self):
        s = ICAPResponse(http=HTTPResponse())

        stream = MagicMock()
        Serializer(s, 'asdf', is_options=False).serialize_to_stream(stream)

        calls = stream.mock_calls[-2:]

        print(calls)
        assert calls == [call.write(b'\r\n'), call.write(b'HTTP/1.1 200 OK\r\n\r\n')]

    def test_serialize_to_stream(self):
        s = ICAPResponse(http=HTTPResponse())

        s.http.body = b'abc'

        stream = MagicMock()
        Serializer(s, 'asdf', is_options=False).serialize_to_stream(stream)

        calls = stream.mock_calls

        print(calls)
        assert calls[1:] == [
            call.write(b'\r\n'),
            call.write(b'HTTP/1.1 200 OK\r\n\r\n'),
            call.write(b'3\r\n'),
            call.write(b'abc\r\n'),
            call.write(b'0\r\n\r\n')
        ]



@pytest.mark.parametrize('is_options', [True, False])
def test_remove_invalid_headers(is_options):
    valid_response_headers = response_headers.pattern[1:-1].split('|')
    valid_options_response_headers = options_response_headers.pattern[1:-1].split('|')

    keys = list(valid_response_headers)
    if is_options:
        keys.extend(valid_options_response_headers)

    keys.append('x-foo')
    valid_keys = sorted(keys)

    keys.append('bad-key')
    keys.append('transfer-encoding')
    keys.sort()

    headers = HeadersDict([(key, 'foo') for key in keys])

    remove_invalid_headers(headers, is_options)

    print(sorted(headers))
    print(sorted(valid_keys))

    assert 'bad-key' not in headers
    assert 'transfer-encoding' not in headers
    assert sorted(headers) == valid_keys
