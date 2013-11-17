import asyncio
import functools
import logging
import re
import time
import uuid

from asyncio.tasks import iscoroutine
from io import BytesIO

from .criteria import AlwaysCriteria, get_handler
from .errors import abort, ICAPAbort, MalformedRequestError
from .models import ICAPResponse, HTTPMessage
from .parsing import ICAPRequestParser
from .serialization import Serializer
from .server import hooks


log = logging.getLogger(__name__)


class ICAPProtocol(asyncio.Protocol):
    def __init__(self, factory):
        self.parser = ICAPRequestParser()
        self.factory = factory
        self._buffer = BytesIO()

    def connection_made(self, transport):
        self.transport = transport
        self.s = time.time()

    def data_received(self, data):
        start = time.time()
        self.transport.pause_reading()

        self._buffer.write(data)
        self._buffer.seek(0)

        if self.parser.headers_complete():
            self.raw_data_received(self._buffer.read())
        else:
            d = self.lines_received()
            if d:
                self.raw_data_received(d)

        p = self.parser

        if p.headers_complete() and p.is_options and 'encapsulated' not in p.headers:
            p.complete(True)

        self.transport.resume_reading()

        if p.complete():
            return asyncio.async(self.handle_request())

    def line_received(self, line):
        self.parser.feed_line(line)

    def lines_received(self):
        try:
            for line in self._buffer:
                self.line_received(line)
                if self.parser.headers_complete():
                    d = self._buffer.read()
                    return d
        except ICAPAbort as e:
            self.respond_with_error(e, should_close=True)
        except (ICAPAbort, MalformedRequestError) as e:
            self.respond_with_error(400, should_close=True)

    def raw_data_received(self, data):
        assert self.parser.headers_complete()

        self.parser.feed_body(data)

    def respond_with_error(self, error, should_close=False):
        response = ICAPResponse.from_error(error)
        self.write_response(response, self.factory.is_tag(None),
                            should_close=should_close)

    @asyncio.coroutine
    def handle_request(self):
        parser, self.parser, self._buffer = self.parser, ICAPRequestParser(), BytesIO()

        request = parser.to_icap()

        should_close = request.headers.get('Connection') == 'close'
        allow_204 = request.allow_204

        try:
            self.factory.validate_request(request)
            handler, raw = get_handler(request, self.factory.strict_when_missing_service)

            hooks['before_handling'](request)

            response = yield from self.factory.handle_request(request, handler, raw)

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

        self.write_response(response, self.factory.is_tag(request),
                            is_options=request.is_options,
                            should_close=should_close)

    def write_response(self, response, is_tag, is_options=False,
                       should_close=False):

        s = Serializer(response, is_tag, is_options=is_options)
        s.serialize_to_stream(self.transport)

        if should_close:
            self.transport.close()


class ICAPProtocolFactory(object):
    def __init__(self, strict_when_missing_service=False):
        """
        ``strict_when_missing_service`` - Decide how to respond when no
        internal services were found matching the given URI of a request (e.g.
        /respmod when the server only supports reqmods). If True, then respond
        with a 404, as decreed by RFC3507. Otherwise (by default), respond with
        204/200. This is useful when the client doesn't handle a 404 very well,
        but it is an indication that the client may be sending more traffic to
        the ICAP server than it should.

        """
        self.strict_when_missing_service = strict_when_missing_service

        fallback_is_tag = uuid.uuid4().hex

        @hooks('is_tag', default=fallback_is_tag)
        def is_tag(request):
            return fallback_is_tag

    def __call__(self):
        return ICAPProtocol(factory=self)

    def is_tag(self, request):
        return '"%s"' % hooks['is_tag'](request)[:32]

    def validate_request(self, request):
        valid_request = (request.is_request and
                         request.request_line.version.startswith('ICAP/'))
        if not valid_request:
            abort(400)
            return

        if not request.request_line.version.endswith('/1.0'):
            abort(505)
            return

        url = request.request_line.uri
        resource = url.path.lower()

        invalid_reqmod = (request.is_reqmod and not re.match('/reqmod/?$', resource))
        invalid_respmod = (request.is_respmod and not re.match('/respmod/?$', resource))

        if not request.is_options and (invalid_reqmod or invalid_respmod):
            abort(405)

    @asyncio.coroutine
    def handle_request(self, request, handler, raw):
        if request.is_options:
            response = yield from self.handle_options(request)
        else:
            response = yield from self.handle_mod(request, handler, raw)
        return response

    @asyncio.coroutine
    def handle_mod(self, request, handler, raw):
        # FIXME: Session support.
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

        http = response
        response = ICAPResponse(http=http)

        if len(http.body) == 1:
            content_length = sum((len(c.content) for c in http.body))
            http.headers.replace('Content-Length', str(content_length))
        elif 'content-length' in http.headers:
            del http.headers['content-length']
            # XXX transfer-encoding chunked should be added?? :/
        return response

    @asyncio.coroutine
    def handle_options(self, request):
        """Handle an OPTIONS request, returning the ICAPResponse object to
        serialize.

        If a request is received for a resource that is not handled, returns
        an ICAP 404.

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
