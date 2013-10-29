import uuid

from StringIO import StringIO

import pytest

from mock import MagicMock, patch, call

from icap import Server, DomainCriteria, HTTPResponse, HeadersDict, HTTPRequest, RegexCriteria


def data_string(req_line, path):
    parts = req_line, open('data/' + path).read()
    return '\r\n'.join(p for p in parts if p)


class TestServer(object):
    def test_start(self):
        s = Server(None)

        one = RegexCriteria(r'foo')
        two = DomainCriteria('*google.com*')
        three = RegexCriteria(r'foo')

        @s.handler(one)
        def respmod():
            pass  # pragma: no cover

        @s.handler(three)
        def respmod():
            pass  # pragma: no cover

        @s.handler(two)
        def respmod():
            pass  # pragma: no cover

        s.start()

        handlers = [i[0] for i in s.handlers['/respmod']]

        print 'expected', [two, one, three]
        print 'actual', handlers
        assert handlers == [two, one, three]

    def test_handle_conn__options_request(self):
        input_bytes = data_string('', 'options_request.request')
        socket = MagicMock()
        fake_stream = StringIO(input_bytes)
        socket.makefile.return_value = fake_stream
        fake_stream.close = lambda: None

        server = Server(None)
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
        s = Server(None)
        s.hooks('is_tag')(lambda request: 'a string')
        assert s.is_tag(None) == '"a string"'

    @pytest.mark.parametrize(('is_tag', 'endswith'), [
        ('1'*31+'2', '2'),
        ('1'*30+'23', '3'),
        ('lamp', 'lamp'),
    ])
    def test_is_tag__maximum_length(self, is_tag, endswith):
        s = Server(None)
        s.hooks('is_tag')(lambda request: is_tag)
        is_tag = s.is_tag(None)
        assert is_tag.endswith(endswith+'"')
        assert len(is_tag) <= 34

    def test_is_tag__error(self):
        with patch.object(uuid.UUID, 'hex', 'cool hash'):
            server = Server(None)

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

        server = Server(None)
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

        server = Server(None)
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

        server = Server(None)
        @server.handler(DomainCriteria('www.origin-server.com'))
        def reqmod(request):
            return HTTPResponse(body='cool body')

        transaction = self.run_test(server, input_bytes)

        assert "HTTP/1.1 200 OK" in transaction
        assert "cool body" in transaction

    def test_handle_conn__request_for_reqmod(self):
        input_bytes = data_string('', 'request_with_http_request_no_payload.request')

        server = Server(None)

        @server.handler(DomainCriteria('www.origin-server.com'))
        def reqmod(request):
            return HTTPRequest(body='cool body', headers=request.headers)

        transaction = self.run_test(server, input_bytes)

        assert "cool body" in transaction

    def test_handle_conn__request_for_respmod(self):
        input_bytes = data_string('', 'icap_request_with_two_header_sets.request')

        server = Server(None)

        @server.handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            return HTTPRequest()

        transaction = self.run_test(server, input_bytes)

        assert "500 Server error" in transaction
        assert transaction.count("This is data that was returned by an origin server") == 1

    def test_handle_conn__response_for_respmod(self):
        input_bytes = data_string('', 'icap_request_with_two_header_sets.request')

        server = Server(None)

        @server.handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            headers = HeadersDict([
                ('Foo', 'bar'),
                ('Bar', 'baz'),
            ])
            return HTTPResponse(headers=headers, body="cool data")

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

        server = Server(None)

        @server.handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            raise exception

        transaction = self.run_test(server, input_bytes)

        assert '500 Server error' in transaction

    def test_handle_conn__handles_socket_errors(self):
        import socket
        server = Server(None)
        s = MagicMock()
        with patch('icap.server.ICAPRequestParser.from_stream', side_effect=socket.error):
            server.handle_conn(s, MagicMock())
        assert s.mock_calls[-1] == call.close()

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

        server = Server(None)
        server.handle_conn(socket, MagicMock())

        s = fake_stream.getvalue()

        print s
        assert expected_message in s

    @pytest.mark.parametrize('force_204', [True, False])
    def test_handle_conn__no_handler(self, force_204):
        input_bytes = data_string('', 'icap_request_with_two_header_sets.request')

        server = Server(None)
        transaction = self.run_test(server, input_bytes, force_204=force_204)

        if force_204:
            assert '204 No modifications needed' in transaction
        else:
            assert '200 OK' in transaction

    @pytest.mark.parametrize('force_204', [True, False])
    def test_handle_conn__empty_return_forces_reserialisation(self, force_204):
        input_bytes = data_string('', 'icap_request_with_two_header_sets.request')

        server = Server(None)

        @server.handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            return

        transaction = self.run_test(server, input_bytes, force_204=force_204)

        assert '200 OK' in transaction
        assert transaction.count('33; lamps') == 2

    def test_handle_conn__string_return(self):
        input_bytes = data_string('', 'icap_request_with_two_header_sets.request')

        server = Server(None)

        @server.handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            return "fooooooooooooooo"

        transaction = self.run_test(server, input_bytes, assert_mutated=True)

        assert "fooooooooooooooo" in transaction

    def test_handle_conn__list_return(self):
        input_bytes = data_string('', 'icap_request_with_two_header_sets.request')

        server = Server(None)

        @server.handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            return ["foo", "bar", "baz"]

        transaction = self.run_test(server, input_bytes, assert_mutated=True,
                                    multi_chunk=True)

        assert "foo" in transaction
        assert "bar" in transaction
        assert "baz" in transaction

    def test_handle_conn__iterable_return(self):
        input_bytes = data_string('', 'icap_request_with_two_header_sets.request')

        server = Server(None)

        @server.handler(DomainCriteria('www.origin-server.com'))
        def respmod(request):
            yield "foo"
            yield "bar"
            yield "baz"

        transaction = self.run_test(server, input_bytes, assert_mutated=True,
                                    multi_chunk=True)

        assert "3\r\nfoo" in transaction
        assert "3\r\nbar" in transaction
        assert "3\r\nbaz\r\n0\r\n" in transaction

    def run_test(self, server, input_bytes, force_204=False,
                 assert_mutated=False, multi_chunk=False):
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

        assert transaction.count('ISTag: ') == 1

        if assert_mutated and not force_204:
            assert transaction.count('Content-Length: 51') == 1
            if not force_204 and not multi_chunk:
                assert transaction.count('Content-Length: ') == 2
            else:
                assert transaction.count('Content-Length: ') == 1

        return transaction

    def test_handle_reqmod(self):
        s = Server(None)

        @s.handler(lambda *args: True)
        def reqmod(self, *args):
            pass  # pragma: no cover

        assert s.get_handler(MagicMock())[0] == reqmod

    def test_handle_respmod(self):
        s = Server(None)

        @s.handler(lambda *args: True)
        def respmod(self, *args):
            pass  # pragma: no cover

        assert s.get_handler(MagicMock(is_reqmod=False))[0] == respmod

    def test_handle_both(self):
        s = Server(None)

        @s.handler(lambda *args: True)
        def respmod(self, *args):
            pass  # pragma: no cover

        @s.handler(lambda *args: True)
        def reqmod(self, *args):
            pass  # pragma: no cover

        assert s.get_handler(MagicMock(is_reqmod=False))[0] == respmod
        assert s.get_handler(MagicMock(is_reqmod=True))[0] == reqmod

    def test_handle_class(self):
        s = Server(None)

        @s.handler(lambda *args: True)
        class Foo(object):
            def reqmod(self, message):
                pass  # pragma: no cover

            def respmod(self, message):
                pass  # pragma: no cover

        print s.handlers
        assert s.get_handler(MagicMock())[0] == s.handlers['/reqmod'][0][1]
        assert s.get_handler(MagicMock(is_reqmod=False))[0] == s.handlers['/respmod'][0][1]

    def test_handle_raw(self):
        s = Server(None)

        called = [False, False]

        reqmod = MagicMock(http='http')
        respmod = MagicMock(is_reqmod=False, http='http')

        @s.handler(lambda *args: True, raw=True)
        class Foo(object):
            def reqmod(self, message):
                assert message != 'http'
                assert message == reqmod
                called[0] = True

            def respmod(self, message):
                assert message != 'http'
                assert message == respmod
                called[1] = True

        s.handle_request(reqmod)
        s.handle_request(respmod)

        assert all(called)

    def test_handle_mapping(self):
        s = Server(None)

        @s.handler(lambda *args: True, name='lamps')
        def reqmod(message):
            pass  # pragma: no cover

        @s.handler(lambda *args: True, name='blarg')
        def respmod(message):
            pass  # pragma: no cover

        print s.handlers.keys()

        mock_request = MagicMock(is_reqmod=True)
        mock_request.request_line.uri = '/lamps/reqmod'
        assert s.get_handler(mock_request)[0] == reqmod

        mock_request = MagicMock(is_reqmod=False)
        mock_request.request_line.uri = '/blarg/respmod'
        assert s.get_handler(mock_request)[0] == respmod

    def test_discover_servers_default_to_gevent(self):
        from gevent.server import StreamServer
        s = Server()
        s.discover_servers()
        assert s.server_class == StreamServer

    def test_discover_servers_fallback(self):
        with patch('gevent.server.StreamServer', None):
            s = Server()
            s.discover_servers()
            assert s.server_class is not None

    def test_discover_servers_complain_on_no_fallbacks(self):
        with patch('gevent.server.StreamServer', None):
            with patch('SocketServer.TCPServer', None):
                s = Server()
                try:
                    s.discover_servers()
                except RuntimeError:
                    pass  # pragma: no cover
                else:
                    assert False, "Should complain when no fallbacks are found"
