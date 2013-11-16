import asyncio
import re
import time

from .criteria import AlwaysCriteria
from .errors import abort, ICAPAbort, MalformedRequestError
from .models import ICAPResponse, HTTPMessage
from .parsing import ICAPRequestParser
from .serialization import Serializer
from .server import Hooks
from .utils import maybe_coroutine, task

from io import BytesIO

import uuid

from collections import defaultdict

import logging

log = logging.getLogger(__name__)


_server = None
_HANDLERS = defaultdict(list)


def run(host='127.0.0.1', port=1334, **kwargs):
    global _server

    factory = ICAPProtocolFactory(**kwargs)
    loop = asyncio.get_event_loop()
    f = loop.create_server(factory, host, port)
    _server = loop.run_until_complete(f)

    loop.run_forever()


def stop():
    assert _server is not None
    _server.close()


def get_handler(request, strict_when_missing_service=False):
    uri = request.request_line.uri
    path = uri.path
    services = _HANDLERS.get(path)

    if not services:
        # RFC3507 says we should abort with 404 if there are no handlers at
        # a given resource - this is fine except when the client (Squid, in
        # this case) relays ICAP 404 responses to the client as internal
        # errors.
        abort(404 if strict_when_missing_service or request.is_options else 204)

    for criteria, handler, raw in services:
        if criteria(request):
            return handler, raw

    if request.is_options:
        handler = lambda req: None
        return handler, False

    abort(204)


def handler(criteria=None, name='', raw=False):
    criteria = criteria or AlwaysCriteria()

    def inner(handler):
        if isinstance(handler, type):
            handler = handler()
            reqmod = getattr(handler, 'reqmod', None)
            respmod = getattr(handler, 'respmod', None)
        else:
            reqmod = handler if handler.__name__ == 'reqmod' else None
            respmod = handler if handler.__name__ == 'respmod' else None

        if reqmod:
            key = '/'.join([name, 'reqmod'])
            key = key if key.startswith('/') else '/%s' % key
            _HANDLERS[key].append((criteria, reqmod, raw))

        if respmod:
            key = '/'.join([name, 'respmod'])
            key = key if key.startswith('/') else '/%s' % key
            _HANDLERS[key].append((criteria, respmod, raw))
        return handler

    return inner


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

            response = yield from self.factory.handle_request(request, handler, raw)

            self.factory.hooks['before_serialization'](request, response)
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
        self.hooks = Hooks()
        self.strict_when_missing_service = strict_when_missing_service

        fallback_is_tag = uuid.uuid4().hex

        @self.hooks('is_tag', default=fallback_is_tag)
        def is_tag(request):
            return fallback_is_tag

    def __call__(self):
        return ICAPProtocol(factory=self)

    def is_tag(self, request):
        return '"%s"' % self.hooks['is_tag'](request)[:32]

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
            f = handler(request)
        else:
            f = handler(request.http)

        response = yield from maybe_coroutine(f)
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

        extra_headers = self.hooks['options_headers']()

        if extra_headers:
            response.headers.update(extra_headers)

        return response
