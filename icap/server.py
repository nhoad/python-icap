from .service import ServiceRegistry
from .models import ICAPRequest, ICAPResponse, Session
from .errors import abort, ICAPAbort


class Server(object):
    def __init__(self, services=None):
        self.services = services or []

    def start(self):
        if not self.services:
            self.services = ServiceRegistry.finalize()

    def handle_conn(self, connection, addr):
        f = connection.makefile()

        while True:
            request = ICAPRequest.from_stream(f)

            if request is None:
                f.close()
                connection.close()
                return

            # FIXME: handle 400 error here.
            assert isinstance(request, ICAPRequest)
            assert request.is_request
            req_version = request.request_line.version
            assert req_version.startswith('ICAP')

            # FIXME: handle 505 error here.
            assert req_version.endswith('/1.0')

            if request.is_options:
                self.handle_options(request)
            else:
                request.session = Session.from_request(request)
                try:
                    response = self.handle_request(request)
                except ICAPAbort as e:
                    if e.status_code == 204 and request.allow_204:
                        response = ICAPResponse.from_error(e)
                    else:
                        response = ICAPResponse.from_request(request)
                else:
                    response = ICAPResponse(http=response)

                if not request.complete():
                    transfer_chunks = ((response.http is not request.http)
                                       and response.http.chunks)
                    if transfer_chunks:
                        response.http.chunks.extend(list(request))
                    else:
                        for _ignored in request.http:
                            pass

                response.http.complete(True)
                response.serialize_to_stream(f)

                # FIXME: if this service doesn't handle respmods, then this
                # would be a memory leak.
                if request.is_respmod:
                    request.session.finished()

    def handle_options(self, request):
        raise NotImplementedError()

    def handle_request(self, request):
        service = None
        for service in self.services:
            if service.can_handle(request):
                break
            else:
                service = None

        if service is None:
            abort(204)

        response = service.handle(request)

        if response is None:
            return request.http
        elif isinstance(response, basestring):
            request.http.set_payload(response)
            return request.http
        elif request.is_respmod and response.is_request:
            abort(500)
        else:
            return response
