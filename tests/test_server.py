import asyncio
import uuid

import pytest

from mock import MagicMock, patch

from icap import (DomainCriteria, HTTPResponse, HeadersDict, HTTPRequest,
                  handler, ICAPProtocolFactory, ICAPProtocol, RequestLine, hooks)
from icap.criteria import _HANDLERS, get_handler
from icap.errors import ICAPAbort
from icap.models import ICAPRequest
from io import BytesIO


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


class TestICAPProtocolFactory(object):
    def setup_method(self, method):
        _HANDLERS.clear()
        hooks.clear()

    def test_validate_request_aborts_400_for_non_icap(self):
        request_line = RequestLine("REQMOD", "/", "HTTP/1.1")
        request = ICAPRequest(request_line)

        try:
            ICAPProtocolFactory().validate_request(request)
        except ICAPAbort as e:
            assert e.status_code == 400

        m = MagicMock(is_request=False)

        try:
            ICAPProtocolFactory().validate_request(m)
        except ICAPAbort as e:
            assert e.status_code == 400

    def test_as_factory(self):
        f = ICAPProtocolFactory()
        t = f()
        assert isinstance(t, ICAPProtocol)
        assert t.factory == f

    @pytest.mark.parametrize('is_tag', [
        'a string',
        lambda request: 'a string',
    ])
    def test_is_tag__valid_values(self, is_tag):
        s = ICAPProtocolFactory()
        hooks('is_tag')(lambda request: 'a string')
        assert s.is_tag(None) == '"a string"'

    @pytest.mark.parametrize(('is_tag', 'endswith'), [
        ('1'*31+'2', '2'),
        ('1'*30+'23', '3'),
        ('lamp', 'lamp'),
    ])
    def test_is_tag__maximum_length(self, is_tag, endswith):
        s = ICAPProtocolFactory()
        hooks('is_tag')(lambda request: is_tag)
        is_tag = s.is_tag(None)
        assert is_tag.endswith(endswith+'"')
        assert len(is_tag) <= 34

    def test_is_tag__error(self):
        with patch.object(uuid.UUID, 'hex', 'cool hash'):
            server = ICAPProtocolFactory()

        @hooks('is_tag')
        def is_tag(request):
            raise Exception('boom')

        assert server.is_tag(None) == '"cool hash"'

    def test_handle_mapping(self):
        @handler(lambda *args: True, name='lamps')
        def reqmod(message):
            pass  # pragma: no cover

        @handler(lambda *args: True, name='blarg')
        def respmod(message):
            pass  # pragma: no cover

        print(list(_HANDLERS.keys()))

        mock_request = MagicMock(is_reqmod=True, is_options=False)
        mock_request.request_line.uri.path = '/lamps/reqmod'
        assert get_handler(mock_request)[0] == reqmod

        mock_request = MagicMock(is_reqmod=False, is_options=False)
        mock_request.request_line.uri.path = '/blarg/respmod'
        assert get_handler(mock_request)[0] == respmod

    def test_handle_reqmod(self):
        @handler(lambda *args: True)
        def reqmod(self, *args):
            pass  # pragma: no cover

        request = MagicMock(http='http', is_options=False)
        request.request_line.uri.path = '/reqmod'

        assert get_handler(request)[0] == reqmod

    def test_handle_respmod(self):
        @handler(lambda *args: True)
        def respmod(self, *args):
            pass  # pragma: no cover

        request = MagicMock(is_reqmod=False, http='http', is_options=False)
        request.request_line.uri.path = '/respmod'

        assert get_handler(request)[0] == respmod

    def test_handle_both(self):
        @handler(lambda *args: True)
        def respmod(self, *args):
            pass  # pragma: no cover

        @handler(lambda *args: True)
        def reqmod(self, *args):
            pass  # pragma: no cover

        request = MagicMock(is_reqmod=False, http='http', is_options=False)
        request.request_line.uri.path = '/respmod'
        assert get_handler(request)[0] == respmod

        request = MagicMock(http='http', is_options=False)
        request.request_line.uri.path = '/reqmod'
        assert get_handler(request)[0] == reqmod

    def test_handle_class(self):
        @handler(lambda *args: True)
        class Foo(object):
            def reqmod(self, message):
                pass  # pragma: no cover

            def respmod(self, message):
                pass  # pragma: no cover

        print(_HANDLERS)

        reqmod = MagicMock(http='http', is_options=False)
        respmod = MagicMock(is_reqmod=False, http='http', is_options=False)
        reqmod.request_line.uri.path = '/reqmod'
        respmod.request_line.uri.path = '/respmod'

        assert get_handler(reqmod)[0] == _HANDLERS['/reqmod'][0][1]
        assert get_handler(respmod)[0] == _HANDLERS['/respmod'][0][1]

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

    def run_test(self, server, input_bytes, force_204=False,
                 assert_mutated=False, multi_chunk=False):
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
            if not force_204 and not multi_chunk:
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
        assert transaction.count(b'33; lamps') == 1

    def test_handle_request__string_return(self):
        input_bytes = data_string('icap_request_with_two_header_sets.request')

        server = ICAPProtocolFactory()

        @handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            return b"fooooooooooooooo"

        transaction = self.run_test(server, input_bytes, assert_mutated=True)

        assert b"fooooooooooooooo" in transaction

    def test_handle_request__list_return(self):
        input_bytes = data_string('icap_request_with_two_header_sets.request')

        server = ICAPProtocolFactory()

        @handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            return [b"foo", b"bar", b"baz"]

        transaction = self.run_test(server, input_bytes, assert_mutated=True,
                                    multi_chunk=True)

        assert b"foo" in transaction
        assert b"bar" in transaction
        assert b"baz" in transaction

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
