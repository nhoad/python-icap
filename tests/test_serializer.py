from mock import MagicMock, call

from icap import ICAPResponse, HTTPResponse
from icap.serializer import Serializer


class TestSerializer(object):
    def test_serialize_options_to_stream(self):
        s = ICAPResponse.from_error(200)
        s.is_options = True

        stream = MagicMock()
        Serializer(s, 'asdf', is_options=True).serialize_to_stream(stream)

        calls = stream.mock_calls[-2:]

        print calls
        assert calls == [call.write('\r\n'), call.flush()]

    def test_serialize_no_body_to_stream(self):
        s = ICAPResponse(http=HTTPResponse())

        stream = MagicMock()
        Serializer(s, 'asdf', is_options=False).serialize_to_stream(stream)

        calls = stream.mock_calls[-2:]

        print calls
        assert calls == [call.write('HTTP/1.1 200 OK\r\n\r\n'), call.flush()]

    def test_serialize_to_stream(self):
        s = ICAPResponse(http=HTTPResponse())

        s.http.body = ['a', 'b', 'c']

        stream = MagicMock()
        Serializer(s, 'asdf', is_options=False).serialize_to_stream(stream)

        calls = stream.mock_calls[-2:]

        print calls
        assert calls == [call.write('0\r\n\r\n'), call.flush()]
