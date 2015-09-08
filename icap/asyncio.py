import asyncio
import functools
import logging
import re

try:
    from asyncio.tasks import iscoroutine
except ImportError:
    from asyncio import iscoroutine
from io import BytesIO, SEEK_END

from .criteria import AlwaysCriteria, get_handler
from .errors import abort, ICAPAbort, MalformedRequestError
from .models import ICAPResponse, HTTPMessage
from .parsing import ICAPRequestParser
from .serialization import Serializer
from .server import hooks, is_tag
from .session import should_finalize_session, finalize_session, get_session


log = logging.getLogger(__name__)


class ICAPProtocol(asyncio.Protocol):
    """Protocol for parsing ICAP requests and serializing ICAP responses."""

    def __init__(self, factory):
        self.parser = ICAPRequestParser()
        self.factory = factory
        self._buffer = BytesIO()
        self.connected = False

    def connection_made(self, transport):
        self.transport = transport
        self.connected = True

    def connection_lost(self, exc):
        self.connected = False

    def data_received(self, data):
        if self.parser.headers_complete():
            self.raw_data_received(data)
        else:
            self._buffer.write(data)
            self._buffer.seek(0)
            self.lines_received()

        p = self.parser

        if p.headers_complete() and p.is_options and 'encapsulated' not in p.headers:
            p.complete(True)

        if p.complete():
            return asyncio.async(self.handle_request())

    def lines_received(self):
        feed_line = self.parser.feed_line
        headers_complete = self.parser.headers_complete

        try:
            for line in self._buffer:
                if not feed_line(line):
                    self.reset_buffer(line)
                    break
                if headers_complete():
                    self.raw_data_received(self._buffer.read())
                    self.reset_buffer()
                    return
            else:
                self.reset_buffer()
        except ICAPAbort as e:
            self.respond_with_error(e, should_close=True)
        except (ICAPAbort, MalformedRequestError) as e:
            self.respond_with_error(400, should_close=True)

    def reset_buffer(self, prefix=b''):
        self._buffer = BytesIO(prefix+self._buffer.read())
        self._buffer.seek(0, SEEK_END)

    def raw_data_received(self, data):
        assert self.parser.headers_complete()

        self.parser.feed_body(data)

    def respond_with_error(self, error, should_close=False):
        """Write an error to the transport as a response to the request.

        ``error`` - either the ICAP error code or an instance of
                    `~icap.errors.ICAPAbort`.
        """
        response = ICAPResponse.from_error(error)
        self.write_response(response, is_tag(None),
                            should_close=should_close)

    @asyncio.coroutine
    def handle_request(self):
        """Handle a single request. Validate it, get a handler for it, and
        dispatch it to `~icap.asyncio.ICAPProtocol.handle_options~ or
        `~icap.asyncio.handle_mod`.

        This is also the principal exception handler.
        """
        parser, self.parser, self._buffer = self.parser, ICAPRequestParser(), BytesIO()

        request = parser.to_icap()

        should_close = request.headers.get('Connection') == 'close'
        allow_204 = request.allow_204

        try:
            self.validate_request(request)
            handler, raw = get_handler(request)

            if not request.is_options:
                hooks['before_handling'](request)
                request.session = yield from maybe_coroutine(get_session, request)

            try:
                response = yield from self.dispatch_request(request, handler, raw)
            finally:
                if should_finalize_session(request):
                    yield from maybe_coroutine(finalize_session, request.session['id'])

            hooks['before_serialization'](request, response)
        except ICAPAbort as e:
            if e.status_code == 204 and not allow_204:
                response = ICAPResponse(http=request.http)
            else:
                response = ICAPResponse.from_error(e)
        except (SystemExit, KeyboardInterrupt):
            raise  # pragma: no cover
        except BaseException:
            log.error("Error while processing %s request",
                      request.request_line.method, exc_info=True)
            response = ICAPResponse.from_error(500)

        self.write_response(response, is_tag(request),
                            is_options=request.is_options,
                            should_close=should_close)

    def write_response(self, response, is_tag, is_options=False,
                       should_close=False):
        """Serialise the given response object to the transport."""

        if not self.connected:
            return

        s = Serializer(response, is_tag, is_options=is_options)
        s.serialize_to_stream(self.transport)

        if should_close:
            self.transport.close()

    def validate_request(self, request):
        """Validate that the given request is a valid ICAP 1.0 request that is
        handled at the given URL.

        """
        valid_request = (request.is_request and
                         request.request_line.version.startswith('ICAP/'))
        if not valid_request:
            abort(400)

        if not request.request_line.version.endswith('/1.0'):
            abort(505)

        url = request.request_line.uri
        resource = url.path.lower()

        invalid_reqmod = (request.is_reqmod and not re.match('/reqmod/?$', resource))
        invalid_respmod = (request.is_respmod and not re.match('/respmod/?$', resource))

        if not request.is_options and (invalid_reqmod or invalid_respmod):
            abort(405)

    @asyncio.coroutine
    def dispatch_request(self, request, handler, raw):
        """Handle a single ICAP request.

        This is just a dispatcher for handle_options and handle_mod.

        Returns an `~icap.models.ICAPResponse` suitable for serialization.

        """
        if request.is_options:
            response = yield from self.handle_options(request)
        else:
            response = yield from self.handle_mod(request, handler, raw)
        return response

    @asyncio.coroutine
    def handle_mod(self, request, handler, raw):
        """Handle a single REQMOD or RESPMOD request.

        Returns an `~icap.models.ICAPResponse` suitable for serialization.

        """
        if raw:
            coro = maybe_coroutine(handler, request)
        else:
            coro = maybe_coroutine(handler, request.http)

        response = yield from coro
        if response is None:
            response = request.http
        elif isinstance(response, HTTPMessage):
            if request.is_respmod and response.is_request:
                abort(500)
        else:
            request.http.body = response
            response = request.http

        assert isinstance(response, HTTPMessage)
        http = response
        response = ICAPResponse(http=http)

        l = len(http.body_bytes)

        if l:
            http.headers.replace('Content-Length', str(l))
        else:
            http.headers.pop('Content-Length', None)
        return response

    @asyncio.coroutine
    def handle_options(self, request):
        """Handle an OPTIONS request, returning the ICAPResponse object to
        serialize.

        Will call the 'options_headers' hook, which is expected to return a
        ``dict`` of headers to append to the ICAP response headers.

        """
        path = request.request_line.uri.path

        response = ICAPResponse()

        response.headers['Methods'] = 'RESPMOD' if path.endswith('respmod') else 'REQMOD'
        response.headers['Allow'] = '204'

        extra_headers = hooks['options_headers']()

        if extra_headers:
            response.headers.update(extra_headers)

        return response


class ICAPProtocolFactory(object):
    """Factory class for creating ICAPProtocol objects."""
    protocol = ICAPProtocol

    def __call__(self):
        return self.protocol(factory=self)


def maybe_coroutine(callable, *args, **kwargs):
    """Invoke a function that may or may not be a coroutine.

    This is analogous to `~twisted.internet.defer.maybeDeferred`, but for
    `asyncio`.

    """

    value = callable(*args, **kwargs)

    if iscoroutine(value):
        return value

    def coro():
        yield
        return value
    return coro()
