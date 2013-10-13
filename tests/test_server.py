from StringIO import StringIO

import pytest

from mock import MagicMock

from icap import Server, DomainService


def data_string(req_line, path):
    parts = req_line, open('data/' + path).read()
    return '\r\n'.join(p for p in parts if p)


class TestServer(object):
    def test_start(self):
        assert False, "Should test that registered Services are added properly."

    def test_handle_conn__options_request(self):
        assert False

    def test_handle_conn__response_for_reqmod(self):
        assert False, "should test handler that returns a response"

    def test_handle_conn__request_for_reqmod(self):
        assert False, "should test handler that returns a request"

    def test_handle_conn__request_for_respmod(self):
        assert False, "should test handler that returns a request, causing a 500 response"

    def test_handle_conn__response_for_respmod(self):
        assert False, "should test handler that returns a response"

    def test_handle_conn__handles_exceptions(self):
        assert False, "should raise a heap of different exceptions, to make sure they're handled."

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

        return transaction