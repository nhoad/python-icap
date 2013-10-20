from mock import MagicMock, call

from icap import ICAPResponse, HTTPResponse
from icap.serialization import Serializer, bodypipe, BodyPart


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


class TestBodyPipe(object):
    def test_consume_set_for_nonstreams(self):
        b = bodypipe([])
        assert b.consumed
        assert not list(b)

        b = bodypipe('blah')
        assert b.consumed
        assert list(b) == [BodyPart('blah', '')]

        def foo():
            yield "one"
            yield "two"
            yield "three"

        b = bodypipe(foo())
        assert b.consumed
        assert list(b) == [
            BodyPart('one', ''),
            BodyPart('two', ''),
            BodyPart('three', ''),
        ]

    def test_consume_not_set_for_streams(self):
        from StringIO import StringIO
        b = bodypipe(StringIO("3\r\nfoo\r\n0\r\n\r\n"))
        assert not b.consumed
        assert list(b) == [BodyPart('foo', '')]
        assert b.consumed

        b = bodypipe(StringIO("3\r\nfoo\r\n0\r\n\r\n"))
        assert not b.consumed
        b.consume()
        assert b.consumed
        assert list(b) == [BodyPart('foo', '')]

    def test_set_consumed_does_not_read_from_stream(self):
        from StringIO import StringIO
        b = bodypipe(StringIO("3\r\nfoo\r\n0\r\n\r\n"))
        assert not b.consumed
        b.consumed = True
        assert b.stream.read() == "3\r\nfoo\r\n0\r\n\r\n"
        assert not list(b)

    def test_wraps_BodyPart_properly(self):
        b = bodypipe(BodyPart('foo', 'bar'))
        assert b.consumed
        assert list(b) == [BodyPart('foo', 'bar')]

    def test_len_stream(self):
        b = bodypipe(['a', 'b', 'c'])
        assert len(b) == 3
        assert b.consumed

    def test_len__nonstream(self):
        from StringIO import StringIO
        b = bodypipe(StringIO("3\r\nfoo\r\n0\r\n\r\n"))

        assert len(b) == 1
        assert b.consumed
