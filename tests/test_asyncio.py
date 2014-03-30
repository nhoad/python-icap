import asyncio

from io import BytesIO

import pytest

from unittest.mock import MagicMock, patch

from icap import (DomainCriteria, HTTPResponse, HeadersDict, HTTPRequest,
                  handler, ICAPProtocolFactory, ICAPProtocol, RequestLine, hooks)
from icap.criteria import _HANDLERS, get_handler
from icap.errors import ICAPAbort
from icap.models import ICAPRequest


def data_string(path):
    return open('data/' + path, 'rb').read()


class BytesIOTransport:
    def __init__(self):
        self._buffer = BytesIO()
        self._paused = False

    def write(self, data):
        self._buffer.write(data)

    def pause_reading(self):
        assert not self._paused, 'Already paused'
        self._paused = True

    def resume_reading(self):
        assert self._paused, 'Already unpaused'
        self._paused = False

    def getvalue(self):
        return self._buffer.getvalue()

    def close(self):
        pass


class TestICAPProtocolFactory:
    def test_as_factory(self):
        f = ICAPProtocolFactory()
        t = f()
        assert isinstance(t, ICAPProtocol)
        assert t.factory == f


class TestICAPProtocol:
    def setup_method(self, method):
        _HANDLERS.clear()

    def test_connection_made_and_lost(self):
        i = ICAPProtocol(None)
        transport = MagicMock()

        assert not i.connected

        i.connection_made(transport)

        assert i.transport == transport
        assert i.connected

        i.connection_lost(None)

        assert not i.connected

    def test_validate_request_aborts_400_for_non_icap(self):
        request_line = RequestLine("REQMOD", "/", "HTTP/1.1")
        request = ICAPRequest(request_line)

        try:
            ICAPProtocol(None).validate_request(request)
        except ICAPAbort as e:
            assert e.status_code == 400
        else:
            assert False

        m = MagicMock(is_request=False)

        try:
            ICAPProtocol(None).validate_request(m)
        except ICAPAbort as e:
            assert e.status_code == 400
        else:
            assert False

    @pytest.mark.parametrize(('input_bytes', 'expected_message'), [
        (b'OPTIONS / HTTP/1.0\r\n\r\n', b'400 Bad Request'),  # HTTP is a no-no
        (b'OPTIONS / ICAP/1.1\r\n\r\n', b'505 ICAP Version Not Supported'),  # invalid version
        (b'OPTIONS /\r\n\r\n', b'400 Bad Request'),  # malformed
        (b'asdf / ICAP/1.0\r\n\r\n', b'501 Method Not Implemented'),
    ])
    def test_malformed_requests_are_handled(self, input_bytes, expected_message):
        s = self.run_test(self.dummy_server(), input_bytes)

        print(s)
        assert expected_message in s

    def dummy_server(self):
        server = ICAPProtocolFactory()

        @handler()
        def reqmod(request):
            pass

        @handler()
        def respmod(request):
            pass

        return server

    @pytest.mark.parametrize('exception', [
        ValueError,
        Exception,
        BaseException,
    ])
    def test_handle_request__handles_exceptions(self, exception):
        input_bytes = data_string('icap_request_with_two_header_sets.request')

        server = ICAPProtocolFactory()

        @handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            raise exception

        transaction = self.run_test(server, input_bytes)

        assert b'500 Internal Server Error' in transaction

    @pytest.mark.parametrize('is_reqmod', [False, True])
    def test_poor_matching_uris_returns_405(self, is_reqmod):
        if is_reqmod:
            path = 'request_with_bad_resource.request'
        else:
            path = 'icap_request_with_two_header_sets_bad_resource.request'
        input_bytes = data_string(path)

        server = ICAPProtocolFactory()

        s = self.run_test(server, input_bytes)

        print(s)
        assert b'405 Method Not Allowed For Service' in s

    def test_multiple_data_received_calls(self):
        expected = HeadersDict([
            ('Host', 'icap.example.org'),
            ('Encapsulated', 'req-hdr=0, res-hdr=137, res-body=296')
        ])

        input_bytes = data_string('icap_request_with_two_header_sets.request')

        server = ICAPProtocolFactory()

        protocol = server()
        protocol.connection_made(BytesIOTransport())

        called = False

        @handler(raw=True)
        def respmod(request):
            nonlocal called
            assert request.is_respmod
            assert request.request_line is not None
            assert request.headers == expected
            assert len(request.http.body) == 51
            called = True

        for b in input_bytes:
            f = protocol.data_received(bytes([b]))

            if f is not None:
                asyncio.get_event_loop().run_until_complete(f)

        t = protocol.transport.getvalue()

        assert protocol.parser.sline is None
        assert not protocol.parser.headers
        assert not protocol.parser.complete()
        print(t)
        assert t
        assert t.count(b'ICAP') == 1
        assert called

    def run_test(self, server, input_bytes, force_204=False,
                 assert_mutated=False):
        if force_204:
            input_bytes = input_bytes.replace(b'Encapsulated', b'Allow: 204\r\nEncapsulated')

        protocol = server()
        protocol.connection_made(BytesIOTransport())

        f = protocol.data_received(input_bytes)

        if f is not None:
            asyncio.get_event_loop().run_until_complete(f)

        transaction = protocol.transport.getvalue()

        print(transaction.decode('utf8'))

        assert transaction.count(b'Date: ') <= 2
        assert transaction.count(b'Encapsulated: ') == 1

        assert transaction.count(b'ISTag: ') == 1

        if assert_mutated and not force_204:
            if not force_204:
                assert transaction.count(b'Content-Length: ') == 1
            else:
                assert transaction.count(b'Content-Length: ') == 0

        return transaction

    def test_handle_request__options_request_no_handlers(self):
        input_bytes = data_string('options_request.request')

        s = self.run_test(ICAPProtocolFactory(), input_bytes)

        print(s)

        assert b'ICAP/1.0 404 ICAP Service Not Found' in s
        assert b'ISTag: ' in s
        assert b'Date: ' in s
        assert b'Encapsulated: ' in s

    def test_handle_request__options_request_handler_with_http_specific_handler(self):
        input_bytes = data_string('options_request.request')

        server = ICAPProtocolFactory()

        @handler(DomainCriteria('google.com'))
        def respmod(request):
            pass

        s = self.run_test(server, input_bytes)

        print(s)

        assert b'ICAP/1.0 200 OK' in s
        assert b'ISTag: ' in s
        assert b'Date: ' in s
        assert b'Encapsulated: ' in s

    def test_handle_request__options_request(self):
        input_bytes = data_string('options_request.request')
        server = self.dummy_server()
        s = self.run_test(server, input_bytes)

        assert b'ICAP/1.0 200 OK' in s
        assert b'Methods: RESPMOD' in s
        assert b'Allow: 204' in s
        assert b'ISTag: ' in s
        assert b'Date: ' in s
        assert b'Encapsulated: ' in s

    def test_handle_request__options_request_failure(self):
        input_bytes = data_string('options_request.request')

        server = self.dummy_server()

        @hooks('options_headers')
        def options_headers():
            raise Exception('noooo')

        s = self.run_test(server, input_bytes)

        print(s)
        assert b'ICAP/1.0 200 OK' in s

    def test_handle_request__options_request_extra_headers(self):
        input_bytes = data_string('options_request.request')
        server = self.dummy_server()

        @hooks('options_headers')
        def options_headers():
            return {
                'Transfer-Complete': '*',
                'Options-TTL': '3600',
            }
        s = self.run_test(server, input_bytes)

        print(s)
        assert b'ICAP/1.0 200 OK' in s
        assert b'Methods: RESPMOD' in s
        assert b'Allow: 204' in s
        assert b'ISTag: ' in s
        assert b'Date: ' in s
        assert b'Encapsulated: ' in s
        assert b'Transfer-Complete: *' in s
        assert b'Options-TTL: 3600' in s

    def test_handle_request__response_for_reqmod(self):
        input_bytes = data_string('request_with_http_request_no_payload.request')

        server = ICAPProtocolFactory()
        @handler(DomainCriteria('www.origin-server.com'))
        def reqmod(request):
            return HTTPResponse(body=b'cool body')

        transaction = self.run_test(server, input_bytes)

        assert b"HTTP/1.1 200 OK" in transaction
        assert b"cool body" in transaction

    def test_handle_request__request_for_reqmod(self):
        input_bytes = data_string('request_with_http_request_no_payload.request')

        server = ICAPProtocolFactory()

        @handler(DomainCriteria('www.origin-server.com'))
        def reqmod(request):
            return HTTPRequest(body=b'cool body', headers=request.headers)

        transaction = self.run_test(server, input_bytes)

        assert b"cool body" in transaction

    @pytest.mark.parametrize(('force_204'), [False, True])
    def test_handle_request__no_match_204(self, force_204):
        input_bytes = data_string('request_with_http_request_no_payload.request')

        server = ICAPProtocolFactory()

        @handler(lambda req: False)
        def reqmod(request):
            return

        transaction = self.run_test(server, input_bytes, force_204=force_204)

        if force_204:
            assert b"ICAP/1.0 204 No Modifications Needed" in transaction
        else:
            assert b"ICAP/1.0 200 OK" in transaction

    def test_handle_request__request_for_respmod(self):
        input_bytes = data_string('icap_request_with_two_header_sets.request')

        server = ICAPProtocolFactory()

        @handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            return HTTPRequest()

        transaction = self.run_test(server, input_bytes)

        assert b"500 Internal Server Error" in transaction
        assert transaction.count(b"This is data that was returned by an origin server") == 0

    def test_handle_request__response_for_respmod(self):
        input_bytes = data_string('icap_request_with_two_header_sets.request')

        server = ICAPProtocolFactory()

        @handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            headers = HeadersDict([
                ('Foo', 'bar'),
                ('Bar', 'baz'),
            ])
            return HTTPResponse(headers=headers, body=b"cool data")

        transaction = self.run_test(server, input_bytes)

        assert b"cool data" in transaction
        assert b"Foo: bar" in transaction
        assert b"Bar: baz" in transaction
        assert transaction.count(b"This is data that was returned by an origin server") == 0

    @pytest.mark.parametrize('force_204', [True, False])
    def test_handle_request__empty_return_forces_reserialization(self, force_204):
        input_bytes = data_string('icap_request_with_two_header_sets.request')

        server = ICAPProtocolFactory()

        @handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            return

        transaction = self.run_test(server, input_bytes, force_204=force_204)

        assert b'200 OK' in transaction
        assert transaction.count(b'33; lamps') == 0
        assert transaction.count(b'33\r\n') == 1

    def test_handle_request__string_return(self):
        input_bytes = data_string('icap_request_with_two_header_sets.request')

        server = ICAPProtocolFactory()

        @handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            return b"fooooooooooooooo"

        transaction = self.run_test(server, input_bytes, assert_mutated=True)

        assert b"fooooooooooooooo" in transaction

    def test_handle_request__raw(self):
        input_bytes = data_string('icap_request_with_two_header_sets.request')

        server = ICAPProtocolFactory()

        @handler(DomainCriteria('www.origin-server.com'), raw=True)
        def respmod(request):
            assert isinstance(request, ICAPRequest)
            return b"fooooooooooooooo"

        transaction = self.run_test(server, input_bytes, assert_mutated=True)

        assert b"fooooooooooooooo" in transaction

    def test_handle_request__coroutines(self):
        input_bytes = data_string('icap_request_with_two_header_sets.request')

        server = ICAPProtocolFactory()

        @handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            yield from asyncio.sleep(0.5)
            return b"fooooooooooooooo"

        transaction = self.run_test(server, input_bytes, assert_mutated=True)

        assert b"fooooooooooooooo" in transaction

    def test_write_response__when_disconnected(self):
        i = ICAPProtocol(False)
        with patch('icap.asyncio.Serializer') as mock_serializer:
            i.write_response(MagicMock(), MagicMock())
            assert not mock_serializer.mock_calls

        i.connection_made(MagicMock())

        with patch('icap.asyncio.Serializer') as mock_serializer:
            i.write_response(MagicMock(), MagicMock())
            assert mock_serializer.mock_calls

    def test_gzip_encoding(self):
        input_bytes = data_string('reddit.com.request')

        server = ICAPProtocolFactory()
        protocol = server()
        protocol.connection_made(BytesIOTransport())

        called = False

        @handler(raw=True)
        def respmod(request):
            nonlocal called
            assert len(request.http.body)
            assert '<!doctype html>' in request.http.body
            assert b'<!doctype html>' in request.http.body_bytes
            called = True

        for b in input_bytes:
            f = protocol.data_received(bytes([b]))

            if f is not None:
                asyncio.get_event_loop().run_until_complete(f)

        t = protocol.transport.getvalue()

        assert protocol.parser.sline is None
        assert not protocol.parser.headers
        assert not protocol.parser.complete()
        print(t)
        assert t
        assert t.count(b'ICAP') == 1
        assert b'<!doctype html>' not in t
        assert called
