from cStringIO import StringIO

from werkzeug import cached_property

from .utils import parse_encapsulated_field, convert_offsets_to_sizes
from .errors import (InvalidEncapsulatedHeadersError, MalformedRequestError,
                     abort)


class ParseState(object):
    empty = 1
    started = 2
    headers_complete = 3


class ChunkedMessageParser(object):
    def __init__(self):
        from .models import HeadersDict
        self.sline = None
        self.headers = HeadersDict()
        self.state = ParseState.empty

    def started(self, set=False):
        if set:
            self.state = ParseState.started
        return self.state != ParseState.empty

    def headers_complete(self, set=False):
        if set:
            self.state = ParseState.headers_complete
        return self.state > ParseState.started

    @classmethod
    def from_stream(cls, stream):
        message = cls()

        complete = message.headers_complete
        while not complete():
            line = stream.readline()

            # Handle a short read, assume the connection was lost.
            # FIXME: non-crlf-endings
            if not line.endswith('\r\n'):
                return None
            message._feed_line(line)

        assert message.headers_complete()

        message.stream = stream
        return message

    @classmethod
    def from_bytes(cls, bytes):
        return cls.from_stream(StringIO(bytes))

    def _feed_line(self, line):
        if not self.started():
            self.handle_status_line(line)
        elif not self.headers_complete():
            self.handle_header(line)

    def handle_status_line(self, sline):
        self.started(True)
        self.sline = parse_start_line(sline.strip())

    def handle_header(self, header):
        # FIXME: non-crlf-endings
        if not header.replace('\r\n', ''):
            self.headers_complete(True)
            return

        # multiline headers
        if header.startswith(('\t', ' ')):
            k = self.headers.keys()[-1]
            v = self.headers.pop(k)

            # section 4.2 says that we MAY reduce whitespace down to a single
            # character, so let's do it.
            v = ' '.join((v, header.strip()))
        else:
            k, v = header.strip().split(':', 1)
            k = k.rstrip()
            v = v.lstrip()

        self.headers[k] = v

    @cached_property
    def is_request(self):
        from .models import RequestLine
        return isinstance(self.sline, RequestLine)

    @cached_property
    def is_response(self):
        return not self.is_request


class ICAPRequestParser(ChunkedMessageParser):
    @classmethod
    def from_stream(cls, stream):
        self = super(ICAPRequestParser, cls).from_stream(stream)

        # handle a short read.
        if self is None:
            return None

        assert self.headers_complete()

        parts = convert_offsets_to_sizes(self.encapsulated_header)

        if self.is_respmod:
            if 'req-hdr' in parts:
                data = self.stream.read(parts['req-hdr'])
                req = HTTPMessageParser.from_bytes(data)
                req_sline = req.request_line
                req_headers = req.headers
            else:
                from .models import HeadersDict
                req_sline = None
                req_headers = HeadersDict()

        missing_headers = ((self.is_reqmod and 'req-hdr' not in parts) or
                           (self.is_respmod and 'res-hdr' not in parts))

        if missing_headers:
            abort(418)
        elif self.is_options and set(parts.keys()) == {'null-body'}:
            m = None
        else:
            # FIXME: As it stands, we don't actually use req-hdr or res-hdr for
            # reading the correct amount for headers here, but rely on the
            # ChunkedMessage parsing.
            m = HTTPMessageParser.from_stream(self.stream)

        self.http = m

        if self.is_respmod:
            m.request_line = req_sline
            m.request_headers = req_headers

        if m is not None and 'null-body' in parts:
            # can't use property magic here. Would try and read from stream,
            # which would break
            m.body.consumed = True
            m.body = []

        return self.to_icap()

    def to_icap(self):
        from .models import ICAPRequest
        return ICAPRequest.from_parser(self)

    def handle_status_line(self, sline):
        super(ICAPRequestParser, self).handle_status_line(sline)

        if self.sline.method not in {'OPTIONS', 'REQMOD', 'RESPMOD'}:
            abort(501)

    @cached_property
    def encapsulated_header(self):
        try:
            e = self.headers['encapsulated']
        except KeyError:
            if self.is_request and self.is_options:
                e = 'null-body=0'
            else:
                raise InvalidEncapsulatedHeadersError(
                    '%s object is missing encapsulated header' %
                    (self.__class__.__name__))
        parsed = parse_encapsulated_field(e)
        return parsed

    @cached_property
    def is_reqmod(self):
        return self.sline.method == 'REQMOD'

    @cached_property
    def is_respmod(self):
        return self.sline.method == 'RESPMOD'

    @cached_property
    def is_options(self):
        return self.sline.method == 'OPTIONS'


class HTTPMessageParser(ChunkedMessageParser):
    @classmethod
    def from_stream(self, stream):
        self = super(HTTPMessageParser, self).from_stream(stream)
        if self is None:
            return None
        return self.to_http()

    def to_http(self):
        from .models import HTTPRequest, HTTPResponse

        if self.is_request:
            cls = HTTPRequest
        else:
            cls = HTTPResponse

        return cls.from_parser(self)


def parse_start_line(sline):
    """Parse the first line from an HTTP/ICAP message and return an instance of
    StatusLine or RequestLine.

    Will raise MalformedRequestError if there was an error during parsing.
    """
    from .models import StatusLine, RequestLine

    try:
        method, uri, version = parts = sline.split(' ', 2)
    except ValueError:
        raise MalformedRequestError

    if method.upper().startswith(('HTTP', 'ICAP')):
        version, code, reason = parts
        try:
            return StatusLine(version.upper(), code, reason)
        except ValueError:
            raise MalformedRequestError
    else:
        return RequestLine(method.upper(), uri, version.upper())
