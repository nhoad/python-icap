import uuid

from StringIO import StringIO

import pytest

from mock import MagicMock, patch

from icap import Server, DomainService, HTTPResponse, HeadersDict, HTTPRequest


def data_string(req_line, path):
    parts = req_line, open('data/' + path).read()
    return '\r\n'.join(p for p in parts if p)


class TestServer(object):
    def test_start(self):
        services = [DomainService('google.com') for i in xrange(10)]
        s = Server()
        s.start()

        assert s.services == services

    def test_handle_conn__options_request(self):
        input_bytes = data_string('', 'options_request.request')
        socket = MagicMock()
        fake_stream = StringIO(input_bytes)
        socket.makefile.return_value = fake_stream
        fake_stream.close = lambda: None

        server = Server()
        server.handle_conn(socket, MagicMock())

        s = fake_stream.getvalue()

        print s

        assert 'ICAP/1.0 200 OK' in s
        assert 'Methods: RESPMOD' in s
        assert 'Allow: 204' in s
        assert 'ISTag: ' in s
        assert 'Date: ' in s
        assert 'Encapsulated: ' in s

    @pytest.mark.parametrize('is_tag', [
        'a string',
        lambda request: 'a string',
    ])
    def test_is_tag__valid_values(self, is_tag):
        s = Server()
        s.hooks('is_tag')(lambda request: 'a string')
        assert s.is_tag(None) == '"a string"'

    @pytest.mark.parametrize(('is_tag', 'endswith'), [
        ('1'*31+'2', '2'),
        ('1'*30+'23', '3'),
        ('lamp', 'lamp'),
    ])
    def test_is_tag__maximum_length(self, is_tag, endswith):
        s = Server()
        s.hooks('is_tag')(lambda request: is_tag)
        is_tag = s.is_tag(None)
        assert is_tag.endswith(endswith+'"')
        assert len(is_tag) <= 34

    def test_is_tag__error(self):
        with patch.object(uuid.UUID, 'hex', 'cool hash'):
            server = Server()

        @server.hooks('is_tag')
        def is_tag(request):
            raise Exception('boom')

        assert server.is_tag(None) == '"cool hash"'

    def test_handle_conn__options_request_failure(self):
        input_bytes = data_string('', 'options_request.request')
        socket = MagicMock()
        fake_stream = StringIO(input_bytes)
        socket.makefile.return_value = fake_stream
        fake_stream.close = lambda: None

        server = Server()
        @server.hooks('options_headers')
        def options_headers():
            raise Exception('noooo')
        server.handle_conn(socket, MagicMock())

        s = fake_stream.getvalue()

        print s
        assert 'ICAP/1.0 200 OK' in s

    def test_handle_conn__options_request_extra_headers(self):
        input_bytes = data_string('', 'options_request.request')
        socket = MagicMock()
        fake_stream = StringIO(input_bytes)
        socket.makefile.return_value = fake_stream
        fake_stream.close = lambda: None

        server = Server()
        @server.hooks('options_headers')
        def options_headers():
            return {
                'Transfer-Complete': '*',
                'Options-TTL': '3600',
            }
        server.handle_conn(socket, MagicMock())

        s = fake_stream.getvalue()

        print s
        assert 'ICAP/1.0 200 OK' in s
        assert 'Methods: RESPMOD' in s
        assert 'Allow: 204' in s
        assert 'ISTag: ' in s
        assert 'Date: ' in s
        assert 'Encapsulated: ' in s
        assert 'Transfer-Complete: *' in s
        assert 'Options-TTL: 3600' in s

    def test_handle_conn__response_for_reqmod(self):
        input_bytes = data_string('', 'request_with_http_request_no_payload.request')

        service = DomainService('www.origin-server.com')

        @service.handler
        def reqmod(request):
            return HTTPResponse(body='cool body')

        server = Server(services=[service])

        transaction = self.run_test(server, input_bytes)

        assert "HTTP/1.1 200 OK" in transaction
        assert "cool body" in transaction

    def test_handle_conn__request_for_reqmod(self):
        input_bytes = data_string('', 'request_with_http_request_no_payload.request')

        service = DomainService('www.origin-server.com')

        @service.handler
        def reqmod(request):
            return HTTPRequest(body='cool body', headers=request.headers)

        server = Server(services=[service])

        transaction = self.run_test(server, input_bytes)

        assert "cool body" in transaction

    def test_handle_conn__request_for_respmod(self):
        input_bytes = data_string('', 'icap_request_with_two_header_sets.request')

        service = DomainService('www.origin-server.com')

        @service.handler
        def respmod(request):
            return HTTPRequest()

        server = Server(services=[service])

        transaction = self.run_test(server, input_bytes)

        assert "500 Server error" in transaction
        assert transaction.count("This is data that was returned by an origin server") == 1

    def test_handle_conn__response_for_respmod(self):
        input_bytes = data_string('', 'icap_request_with_two_header_sets.request')

        service = DomainService('www.origin-server.com')

        @service.handler
        def respmod(request):
            headers = HeadersDict([
                ('Foo', 'bar'),
                ('Bar', 'baz'),
            ])
            return HTTPResponse(headers=headers, body="cool data")

        server = Server(services=[service])

        transaction = self.run_test(server, input_bytes)

        assert "cool data" in transaction
        assert "Foo: bar" in transaction
        assert "Bar: baz" in transaction
        assert transaction.count("This is data that was returned by an origin server") == 1

    @pytest.mark.parametrize('exception', [
        ValueError,
        StandardError,
        Exception,
        BaseException,
    ])
    def test_handle_conn__handles_exceptions(self, exception):
        input_bytes = data_string('', 'icap_request_with_two_header_sets.request')

        service = DomainService('www.origin-server.com')

        @service.handler
        def respmod(request):
            raise exception

        server = Server(services=[service])

        transaction = self.run_test(server, input_bytes)

        assert '500 Server error' in transaction

    @pytest.mark.parametrize(('input_bytes', 'expected_message'), [
        ('OPTIONS / HTTP/1.0\r\n\r\n', '400 Bad request'),  # HTTP is a no-no
        ('OPTIONS / ICAP/1.1\r\n\r\n', '505 ICAP version not supported'),  # invalid version
        ('OPTIONS /\r\n\r\n', '400 Bad request'),  # malformed
        ('asdf / ICAP/1.0\r\n\r\n', '501 Method not implemented'),
    ])
    def test_non_icap_request_returns_400(self, input_bytes, expected_message):
        socket = MagicMock()
        fake_stream = StringIO(input_bytes)
        socket.makefile.return_value = fake_stream
        fake_stream.close = lambda: None

        server = Server()
        server.handle_conn(socket, MagicMock())

        s = fake_stream.getvalue()

        print s
        assert expected_message in s

    @pytest.mark.parametrize('force_204', [True, False])
    def test_handle_conn__no_handler(self, force_204):
        input_bytes = data_string('', 'icap_request_with_two_header_sets.request')

        server = Server()
        transaction = self.run_test(server, input_bytes, force_204=force_204)

        if force_204:
            assert '204 No modifications needed' in transaction
        else:
            assert '200 OK' in transaction

    @pytest.mark.parametrize('force_204', [True, False])
    def test_handle_conn__empty_return_forces_reserialisation(self, force_204):
        input_bytes = data_string('', 'icap_request_with_two_header_sets.request')
        service = DomainService('www.origin-server.com')

        @service.handler
        def respmod(request):
            return

        server = Server(services=[service])
        transaction = self.run_test(server, input_bytes, force_204=force_204)

        assert '200 OK' in transaction

    def test_handle_conn__string_return(self):
        input_bytes = data_string('', 'icap_request_with_two_header_sets.request')

        service = DomainService('www.origin-server.com')

        @service.handler
        def respmod(request):
            return "fooooooooooooooo"

        server = Server(services=[service])

        transaction = self.run_test(server, input_bytes)

        assert "fooooooooooooooo" in transaction

    def run_test(self, server, input_bytes, force_204=False):
        if force_204:
            input_bytes = input_bytes.replace('Encapsulated', 'Allow: 204\r\nEncapsulated')

        socket = MagicMock()

        fake_stream = StringIO(input_bytes)
        # so we can print it out at the end
        fake_stream.close = lambda: None

        socket.makefile.return_value = fake_stream
        server.handle_conn(socket, MagicMock())
        transaction = fake_stream.getvalue()

        print transaction

        assert transaction.count('Date: ') >= 2
        assert transaction.count('Encapsulated: ') == 2

        assert 'ISTag: ' in transaction

        return transaction
