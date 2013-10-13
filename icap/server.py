from .service import ServiceRegistry
from .models import ICAPRequest, ICAPResponse, Session
from .errors import abort, ICAPAbort, MalformedRequestError


class Server(object):
    """Server, for handling requests on a given address."""

    def __init__(self, services=None):
        self.services = services or []

    def start(self):
        if not self.services:
            self.services = ServiceRegistry.finalize()

    def handle_conn(self, connection, addr):
        """Handle a single connection. May handle many requests."""

        f = connection.makefile()

        def respond_with_error(error):
            # Clients are required to be aware of early returns, so sending an
            # error back without reading everything up should be fine. If not,
            # then, it's their fault for sending us invalid requests.
            response = ICAPResponse.from_error(error)
            response.serialize_to_stream(f)
            f.close()
            connection.close()

        while True:
            try:
                request = ICAPRequest.from_stream(f)
            except MalformedRequestError as e:
                respond_with_error(400)
                return

            # connection was closed or some such.
            if request is None:
                f.close()
                connection.close()
                return

            valid_request = (request.is_request and
                             request.request_line.version.startswith('ICAP/'))
            if not valid_request:
                respond_with_error(400)
                return

            if not request.request_line.version.endswith('/1.0'):
                respond_with_error(505)
                return

            if request.is_options:
                self.handle_options(request)
            else:
                request.session = Session.from_request(request)
                try:
                    response = self.handle_request(request)
                except ICAPAbort as e:
                    if e.status_code == 204 and not request.allow_204:
                        response = ICAPResponse.from_request(request)
                    else:
                        response = ICAPResponse.from_error(e)
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
        """Handle an OPTIONS request."""
        raise NotImplementedError()

    def handle_request(self, request):
        """Handle a REQMOD or RESPMOD request."""
        service = None
        for service in self.services:
            if service.can_handle(request):
                break
            else:
                service = None

        if service is None:
            abort(204)

        try:
            response = service.handle(request)
        except (SystemExit, KeyboardInterrupt) as e:
            raise
        except BaseException as e:
            # FIXME: communicating this exception in some way would be nice.
            abort(500)

        if response is None:
            return request.http
        elif isinstance(response, basestring):
            request.http.set_payload(response)
            return request.http
        elif request.is_respmod and response.is_request:
            abort(500)
        else:
            return response
