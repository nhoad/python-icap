import gzip

from collections import namedtuple
from io import BytesIO, SEEK_END

from werkzeug import cached_property

from .utils import parse_encapsulated_field, convert_offsets_to_sizes
from .errors import (InvalidEncapsulatedHeadersError, MalformedRequestError,
                     abort)


__all__ = [
    'ChunkedMessageParser',
    'ICAPRequestParser',
    'HTTPMessageParser',
]


# who could resist a class name like this?
BodyPart = namedtuple('BodyPart', 'content header')

class ParseState(object):
    empty = 1
    started = 2
    headers_complete = 3
    body_complete = 4


class ChunkParsingError(Exception):
    pass


class ChunkedMessageParser(object):
    def __init__(self):
        from .models import HeadersDict
        self.sline = None
        self.headers = HeadersDict()
        self.state = ParseState.empty
        self.body = BytesIO()
        self.chunks = []

    def started(self, set=False):
        if set:
            self.state = ParseState.started
        return self.state != ParseState.empty

    def headers_complete(self, set=False):
        if set:
            self.state = ParseState.headers_complete
            self.on_headers_complete()
        return self.state > ParseState.started

    def on_headers_complete(self):
        pass

    def on_complete(self):
        pass

    def complete(self, set=False):
        if set:
            self.state = ParseState.body_complete
            self.on_complete()
        return self.state == ParseState.body_complete

    def feed_line(self, line):
        if isinstance(line, bytes):
            line = line.decode('utf8')

        # FIXME: non-crlf-endings
        if not line.endswith('\r\n'):
            return False

        if not self.started():
            self.handle_status_line(line)
        elif not self.headers_complete():
            self.handle_header(line)

        return True

    def feed_body(self, data):
        self.body.write(data)
        self.body.seek(0)
        try:
            while not self.complete():
                self.attempt_body_parse()
        except ChunkParsingError:
            pass
        finally:
            self.body.seek(0, SEEK_END)

    @classmethod
    def from_bytes(cls, bytes):
        self = cls()
        stream = BytesIO(bytes)

        while not self.headers_complete():
            line = stream.readline()
            if not self.feed_line(line):
                raise MalformedRequestError('Line not valid: %r' % line)

        s = stream.read()
        if s:
            self.feed_body(s)
        else:
            self.complete(True)

        assert self.complete()
        return self

    def attempt_body_parse(self):
        raise NotImplementedError()

    def handle_status_line(self, sline):
        assert not self.started()
        self.started(True)
        self.sline = parse_start_line(sline.strip())

    def handle_header(self, header):
        # FIXME: non-crlf-endings
        if not header.replace('\r\n', ''):
            self.headers_complete(True)
            return

        header = header.replace('\r\n', '')

        # multiline headers
        if header.startswith(('\t', ' ')):
            k = list(self.headers.keys())[-1]
            from collections import OrderedDict
            raw_v = OrderedDict.__getitem__(self.headers, k)
            k, v = raw_v[-1]

            # section 4.2 says that we MAY reduce whitespace down to a single
            # character, so let's do it.
            v = ''.join((v, header.lstrip()))

            raw_v[-1] = k, v
        else:
            k, v = header.split(':', 1)
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
    def on_headers_complete(self):
        self.encapsulated_parts = list(
            convert_offsets_to_sizes(self.encapsulated_header).items())

        parts = self.encapsulated_header
        missing_headers = ((self.is_reqmod and 'req-hdr' not in parts) or
                           (self.is_respmod and 'res-hdr' not in parts))

        if missing_headers:
            abort(418)

        self.request_parser = HTTPMessageParser()
        self.response_parser = HTTPMessageParser()

    def attempt_body_parse(self):
        name, size = self.encapsulated_parts[0]
        data = self.body.read(size)

        if size > 0 and len(data) != size:
            raise ChunkParsingError

        if size == -1 and not data:
            raise ChunkParsingError

        if size == 0:
            assert name == 'null-body'
            assert not data

        if name in ('req-hdr', 'req-body'):
            parser = self.request_parser
        elif name in ('res-hdr', 'res-body'):
            parser = self.response_parser

        if name in ('req-hdr', 'res-hdr'):
            self.encapsulated_parts.pop(0)
            buffer = BytesIO(data)
            for line in buffer:
                parser.feed_line(line)
            assert parser.headers_complete()
        elif name in ('req-body', 'res-body'):
            self.body.seek(0)
            self.body.truncate()
            assert parser.headers_complete()
            parser.feed_body(data)

            if parser.complete():
                self.encapsulated_parts.pop(0)
            else:
                raise ChunkParsingError
        else:
            if self.is_reqmod:
                parser = self.request_parser
            else:
                parser = self.response_parser
            assert parser.headers_complete()
            assert name == 'null-body'
            self.request_parser.complete(True)
            self.response_parser.complete(True)

        self.body = BytesIO(self.body.read())

    def complete(self, set=False):
        if set:
            super().complete(set)
        return super().complete() or (self.headers_complete() and (
            (self.is_reqmod and self.request_parser.complete()) or
            (self.is_respmod and self.response_parser.complete()) or
            (self.is_options)
        ))

    @classmethod
    def from_bytes(cls, bytes):
        self = super().from_bytes(bytes)
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
    payload = b''

    def attempt_body_parse(self):
        while True:
            chunk = self.attempt_parse_chunk()
            if chunk is None:
                assert self.complete()
                break
            self.chunks.append(chunk)

    @cached_property
    def is_gzipped(self):
        return 'gzip' in self.headers.get('Content-Encoding', '')

    def on_complete(self):
        payload = b''.join(b.content for b in self.chunks)
        if self.is_gzipped:
            # FIXME: this should be done in a thread
            payload = gzip.decompress(payload)
        self.payload = payload

    def attempt_parse_chunk(self):
        line = self.body.readline()

        # FIXME: non-crlf-endings
        if not line.endswith(b'\r\n'):
            raise ChunkParsingError
        else:
            try:
                size, header = line.split(b';', 1)
            except ValueError:
                size = line
                header = b''

            size = int(size, 16)
            if size:
                # FIXME: non-crlf-endings
                data = self.body.read(size+2)  # +2 for CRLF

                if len(data) != size+2:
                    raise ChunkParsingError

                # reset the stream so we don't create the same chunk over and over
                self.body = BytesIO(self.body.read())

                # FIXME: non-crlf-endings
                chunk = BodyPart(data[:-2], header.strip())
                return chunk
            else:
                # end of stream, make sure we have trailing newline
                s = self.body.readline()

                # FIXME: non-crlf-endings
                if s != b'\r\n':
                    raise ChunkParsingError

                self.complete(True)

    @classmethod
    def from_bytes(cls, bytes):
        self = super().from_bytes(bytes)
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
        raise MalformedRequestError('Malformed start line: %r' % sline)

    if method.upper().startswith(('HTTP', 'ICAP')):
        version, code, reason = parts
        try:
            return StatusLine(version.upper(), code, reason)
        except ValueError:
            raise MalformedRequestError('Malformed status line: %r' % sline)
    else:
        return RequestLine(method.upper(), uri, version.upper())
