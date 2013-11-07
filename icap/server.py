import logging
import re
import socket
import time
import uuid

from types import ClassType, TypeType
from collections import defaultdict

from .criteria import AlwaysCriteria
from .models import ICAPResponse, Session, HTTPMessage, StatusLine
from .serialization import Serializer, StreamBodyPipe
from .errors import abort, ICAPAbort, MalformedRequestError
from .parsing import ICAPRequestParser

log = logging.getLogger(__name__)


class Hooks(dict):
    """Dispatch class for providing hooks at certain parts of the ICAP
    transaction.

    Used on a server instance like so:

    >>> from icap.server import Server
    >>> server = Server()
    >>> @server.hooks('options_headers')
    >>> def extra_headers():
    ...     return {'new': 'headers'}


    Available hooks:
        options_headers:
            Return dictionary of additional headers to add to the OPTIONS
            response.

            arguments: None.

        is_tag:
            Return a string to be used for a custom ISTag header on the
            response. String will be sliced to maximum of 32 bytes.

            arguments: request object, may be None.

    """
    def __getitem__(self, name):
        """Return the callable hook matching *name*.

        Always returns a callable that won't raise an exception.

        """

        if name in self:
            func, default = dict.__getitem__(self, name)
        else:
            func = lambda *args: None
            default = None

        def safe_callable(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception:
                return default
        return safe_callable

    def __call__(self, name, default=None, override=False):
        """Register a hook function with *name*, and *default* return value.

        Unless *override* is True, then *default* will only be saved the for
        the first time. This is to ensure sane defaults are used in the event
        that an error occurs in the registered hook.

        """
        # we want to keep the original default, as it will be used if the new
        # one fails, e.g. for the ISTag header.
        if name in self and not override:
            _oldfunc, default = dict.__getitem__(self, name)

        def wrapped(func):
            self[name] = func, default
        return wrapped


class Server(object):
    """Server, for handling requests on a given address."""

    def __init__(self, server_class=None, strict_when_missing_service=False):
        """
        ``server_class`` - class used for accepting connections. Must support
        interface as defined by `~icap.server.Server.run`.

        ``strict_when_missing_service`` - Decide how to respond when no
        internal services were found matching the given URI of a request (e.g.
        /respmod when the server only supports reqmods). If True, then respond
        with a 404, as decreed by RFC3507. Otherwise (by default), respond with
        204/200. This is useful when the client doesn't handle a 404 very well,
        but it is an indication that the client may be sending more traffic to
        the ICAP server than it should.
        """
        self.server_class = server_class
        self.running = True
        self.handlers = defaultdict(list)
        self.hooks = Hooks()
        self.connections = []
        self.strict_when_missing_service = strict_when_missing_service

        fallback_is_tag = uuid.uuid4().hex

        @self.hooks('is_tag', default=fallback_is_tag)
        def is_tag(request):
            return fallback_is_tag

    def run(self, server_address=('0.0.0.0', 1334)):
        """Run the given server class with `server_address` and ``self.handle_conn``.

        This method will block until the server is stopped.
        """
        self.running = True
        if self.server_class is None:
            self.discover_servers()
        self.server = self.server_class(server_address, self.handle_conn)
        self.server.serve_forever()

    def stop(self):
        """Stop the server, if it is running."""
        if self.running:
            for method in KNOWN_STOP_METHODS:
                stop = getattr(self.server, method, None)

                if stop is not None:
                    stop()
                    break

        # FIXME: this should have a configurable timeout.
        while self.connections:
            time.sleep(1)

    def is_tag(self, request):
        return '"%s"' % self.hooks['is_tag'](request)[:32]

    def start(self):
        for key, value in self.handlers.iteritems():
            self.handlers[key] = sorted(value, key=lambda item: item[0])

    def handle_conn(self, connection, addr, server=None):
        """Handle a single connection. May handle many requests.

        ``connection`` - the ``socket``-(like) object connection to the client. Must
        support both `makefile` and `close` operations.

        ``addr`` - tuple of the client address and connected port.

        ``server`` - Will be ``self.server`` if you're using something like
        :class:`SocketServer.TCPServer`. None otherwise.
        """
        self.connections.append(connection)

        f = connection.makefile()

        def close():
            f.close()
            connection.close()
            self.connections.remove(connection)

        def respond_with_error(error, should_close):
            # Clients are required to be aware of early returns, so sending an
            # error back without reading everything up should be fine. If not,
            # then, it's their fault for sending us invalid requests.
            response = ICAPResponse.from_error(error)
            if should_close:
                response.headers['Connection'] = 'close'
            s = Serializer(response, self.is_tag(None), is_options=False,
                           should_close=should_close)
            s.serialize_to_stream(f)

        while True:
            try:
                request = ICAPRequestParser.from_stream(f)
            except socket.error:
                # probably ECONNRESET. FIXME: logging
                request = None
            except MalformedRequestError as e:
                respond_with_error(400, should_close=False)
                return
            except ICAPAbort as e:
                respond_with_error(e, should_close=False)
                return

            # connection was closed or some such.
            if request is None:
                close()
                return

            # Squid doesn't send Connection: close headers for OPTIONS requests.
            should_close = request.is_options or (request.headers.get('Connection') == 'close')

            valid_request = (request.is_request and
                             request.request_line.version.startswith('ICAP/'))
            if not valid_request:
                respond_with_error(400, should_close=should_close)
                return

            if not request.request_line.version.endswith('/1.0'):
                respond_with_error(505, should_close=should_close)
                return

            url = request.request_line.uri
            resource = url.path.lower()

            invalid_reqmod = (request.is_reqmod and not re.match('/reqmod/?$', resource))
            invalid_respmod = (request.is_respmod and not re.match('/respmod/?$', resource))

            if not request.is_options and (invalid_reqmod or invalid_respmod):
                respond_with_error(405, should_close=should_close)
                return

            if request.is_options:
                response = self.handle_options(request)
            else:
                try:
                    response = self.handle_mod(request)
                except ICAPAbort as e:
                    if request.has_body and isinstance(request.http.body, StreamBodyPipe):
                        request.http.body.consume()
                    if e.status_code == 204 and not request.allow_204:
                        response = ICAPResponse(http=request.http)
                    else:
                        response = ICAPResponse.from_error(e)

            self.hooks['before_serialization'](request, response)

            s = Serializer(
                response, self.is_tag(request), is_options=request.is_options,
                should_close=should_close)
            s.serialize_to_stream(f)

            if should_close:
                close()
                return

    def handle_mod(self, request):
        request.session = Session.from_request(request)

        has_body = request.has_body
        response = self.handle_request(request)
        response = ICAPResponse(http=response)

        if has_body and isinstance(request.http.body, StreamBodyPipe):
            request.http.body.consume()

        if response.status_line.code == 200:
            transfer_chunks = ((response.http is not request.http)
                               and not response.http.body)
            if transfer_chunks:
                response.http.body = request.http.body

            http = response.http

            if len(http.body) == 1:
                content_length = sum((len(c.content) for c in http.body))
                http.headers.replace('Content-Length', str(content_length))
            elif 'content-length' in http.headers:
                del http.headers['content-length']

        # FIXME: if this service doesn't handle respmods, then this
        # would be a memory leak.
        if request.is_respmod:
            request.session.finished()
        return response

    def handle_options(self, request):
        """Handle an OPTIONS request, returning the ICAPResponse object to
        serialize.

        If a request is received for a resource that is not handled, returns
        an ICAP 404.

        Will call the 'options_headers' hook, which is expected to return a
        ``dict`` of headers to append to the ICAP response headers.

        """
        path = request.request_line.uri.path

        try:
            self.get_handler(request)
        except ICAPAbort as e:
            return ICAPResponse(StatusLine('ICAP/1.0', 404))

        response = ICAPResponse()

        response.headers['Methods'] = 'RESPMOD' if path.endswith('respmod') else 'REQMOD'
        response.headers['Allow'] = '204'

        extra_headers = self.hooks['options_headers']()

        if extra_headers:
            response.headers.update(extra_headers)

        return response

    def get_handler(self, request):
        uri = request.request_line.uri
        path = uri.path
        services = self.handlers.get(path)

        if not services:
            # RFC3507 says we should abort with 404 if there are no handlers at
            # a given resource - this is fine except when the client (Squid, in
            # this case) relays ICAP 404 responses to the client as internal
            # errors.
            abort(404 if self.strict_when_missing_service else 204)

        for criteria, handler, raw in services:
            if criteria(request):
                return handler, raw
        return None, False

    def handle_request(self, request):
        """Handle a REQMOD or RESPMOD request."""
        handler, raw = self.get_handler(request)
        if handler is None:
            abort(204)

        try:
            if raw:
                response = handler(request)
            else:
                response = handler(request.http)

        except (SystemExit, KeyboardInterrupt):
            raise  # pragma: no cover
        except BaseException:
            log.error("Error while processing %s request",
                      request.request_line.method, exc_info=True)
            abort(500)

        if response is None:
            return request.http
        elif isinstance(response, HTTPMessage):
            if request.is_respmod and response.is_request:
                abort(500)
            return response
        else:
            request.http.body = response
            assert request.http.body.consumed
            return request.http

    def handler(self, criteria=None, name='', raw=False):
        criteria = criteria or AlwaysCriteria()

        def inner(handler):
            if isinstance(handler, (ClassType, TypeType)):
                handler = handler()
                reqmod = getattr(handler, 'reqmod', None)
                respmod = getattr(handler, 'respmod', None)
            else:
                reqmod = handler if handler.__name__ == 'reqmod' else None
                respmod = handler if handler.__name__ == 'respmod' else None

            if reqmod:
                key = '/'.join([name, 'reqmod'])
                key = key if key.startswith('/') else '/%s' % key
                self.handlers[key].append((criteria, reqmod, raw))

            if respmod:
                key = '/'.join([name, 'respmod'])
                key = key if key.startswith('/') else '/%s' % key
                self.handlers[key].append((criteria, respmod, raw))
            return handler

        return inner

    def discover_servers(self):
        """In order of best to worst, try to find a suitable socket server to
        use.

        Only used if a server class was not passed in when Server instance was
        created.
        """
        for module, server in KNOWN_SERVERS:
            try:
                module = __import__(module, fromlist=[server])
            except ImportError:
                pass
            else:
                self.server_class = getattr(module, server, None)
                if self.server_class is not None:
                    log.info("Using %s for accepting connections.",
                             self.server_class.__name__)
                    return

        if self.server_class is None:
            raise RuntimeError(
                "No supported socket servers could be found. Please install "
                "one or pass a compatible socket server along when "
                "instantiating a Server class.")


KNOWN_SERVERS = [
    ('gevent.server', 'StreamServer'),
    ('SocketServer', 'TCPServer'),
]

KNOWN_STOP_METHODS = [
    'stop',  # gevent
    'shutdown',  # SocketServer
]
