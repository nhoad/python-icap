import urlparse

from collections import namedtuple, OrderedDict

from werkzeug import http_date, cached_property

from .errors import (
    InvalidEncapsulatedHeadersError,
    MalformedRequestError,
    abort,
    response_codes)

from .utils import dump_encapsulated_field
from .parsing import ICAPRequestParser

# who could resist a class name like this?
BodyPart = namedtuple('BodyPart', 'content header')
RequestLine = namedtuple('RequestLine', 'method uri version')
StatusLine = namedtuple('StatusLine', 'version code reason')


class HeadersDict(OrderedDict):
    """Multivalue, case-aware dictionary type used for headers of requests and
    responses.

    """
    def __init__(self, items=()):
        OrderedDict.__init__(self)
        for key, value in items:
            self[key] = value

    def __setitem__(self, key, value):
        lkey = key.lower()

        if lkey not in self:
            OrderedDict.__setitem__(self, lkey, [(key, value)])
        else:
            OrderedDict.__getitem__(self, lkey).append((key, value))

    def __getitem__(self, key):
        """Return the first value stored at `key`."""
        return OrderedDict.__getitem__(self, key.lower())[0][1]

    def get(self, key, default=None):
        try:
            return self.__getitem__(key)
        except KeyError:
            return default

    def getlist(self, key, default=list):
        """Return all values stored at `key`."""
        try:
            return [v for k, v in OrderedDict.__getitem__(self, key.lower())]
        except KeyError:
            return default()

    def replace(self, key, value):
        """Replace all values at `key` with `value`."""
        lkey = key.lower()
        OrderedDict.__setitem__(self, lkey, [(key, value)])

    def __eq__(self, other):
        if self.keys() != other.keys():
            return False

        for key in self.keys():
            value = OrderedDict.__getitem__(self, key)
            ovalue = OrderedDict.__getitem__(other, key)

            if value != ovalue:
                return False

        return True

    def __str__(self):
        """Return a string of the headers, suitable for writing to a stream."""
        if not self:
            return ''

        s = '\r\n'.join(
            ': '.join(v) for k in self
            for v in OrderedDict.__getitem__(self, k)
        ) + '\r\n'

        return s


class ICAPMessage(object):
    def __init__(self, headers=None, http=None):
        self.headers = headers or HeadersDict()

        # really not comfortable with this default...
        self.http = http

    @cached_property
    def is_request(self):
        return not self.is_response

    @cached_property
    def is_response(self):
        return isinstance(self, ICAPResponse)

    @cached_property
    def has_body(self):
        return 'null-body' not in self.headers['encapsulated']


class ICAPRequest(ICAPMessage):
    def __init__(self, request_line=None, *args, **kwargs):
        super(ICAPRequest, self).__init__(*args, **kwargs)
        self.request_line = request_line or RequestLine('ICAP/1.1', 200, 'OK')

    @classmethod
    def from_parser(cls, parser):
        assert isinstance(parser, ICAPRequestParser)

        self = cls(parser.sline, parser.headers, parser.http)
        return self

    @cached_property
    def allow_204(self):
        return '204' in self.headers.get('allow', '')

    @cached_property
    def is_reqmod(self):
        return self.request_line.method == 'REQMOD'

    @cached_property
    def is_respmod(self):
        return self.request_line.method == 'RESPMOD'

    @cached_property
    def is_options(self):
        return self.request_line.method == 'OPTIONS'


class ICAPResponse(ICAPMessage):
    def __init__(self, status_line=None, is_options=False, *args, **kwargs):
        super(ICAPResponse, self).__init__(*args, **kwargs)
        self.status_line = status_line or StatusLine('ICAP/1.0', 200, 'OK')

        # XXX: once the reserialization is moved out of this object, this can
        # go.
        self.is_options = is_options

    def __str__(self):
        return '\r\n'.join([' '.join(map(str, self.status_line)), str(self.headers)])

    @classmethod
    def from_error(cls, error):
        if isinstance(error, int):
            status_code = error
        else:
            status_code = error.status_code
        message = response_codes[status_code]
        self = cls(StatusLine('ICAP/1.0', status_code, message))
        return self

    def serialize_to_stream(self, stream, is_tag):
        """Serialize the ICAP response and contained HTTP message to *stream*."""
        self.set_required_headers(is_tag)

        http_preamble = self.set_encapsulated_header()

        if self.status_line.code != 200 or self.is_options:
            stream.write(str(self))
            stream.write('\r\n')
            stream.flush()
            return

        # FIXME: need to serialize opt-body requests too.

        stream.write(str(self))
        stream.write('\r\n')
        stream.write(http_preamble)

        self.write_body(stream)

    def set_required_headers(self, is_tag):
        """Sets headers required for the ICAP response."""
        self.headers['Date'] = http_date()
        self.headers['ISTag'] = is_tag

    def write_body(self, stream):
        """Write out each chunk to the given stream."""
        if not self.http.body:
            stream.flush()
            return

        for chunk in self.http.body:
            s = chunk.content
            n = hex(len(s))[2:]  # strip off leading 0x

            header = chunk.header.strip()
            if header and header != 'ieof':
                header = '%s; %s' % (n, header)
            else:
                header = n

            stream.write(header+'\r\n')
            stream.write(s+'\r\n')

        stream.write('0\r\n\r\n')
        stream.flush()

    def set_encapsulated_header(self):
        """Serialize the http message preamble, set the encapsulated header,
        and return the serialized preamble.
        """
        if self.status_line.code != 200 or self.is_options:
            encapsulated = OrderedDict([('null-body', 0)])
            http_preamble = ''
        else:
            http = self.http
            http_preamble = str(http) + '\r\n'

            if http.is_request:
                encapsulated = OrderedDict([('req-hdr', 0)])
                body_key = 'req-body'
            else:
                encapsulated = OrderedDict([('res-hdr', 0)])
                body_key = 'res-body'

            if not http or not http.body:
                body_key = 'null-body'

            encapsulated[body_key] = len(http_preamble)

        self.headers['Encapsulated'] = dump_encapsulated_field(encapsulated)

        return http_preamble


class HTTPMessage(object):
    def __init__(self, headers=None, body=None):
        self.headers = headers or HeadersDict()
        self.__body = None
        self.body = BodyPipe(body or [])

    @property
    def body(self):
        return self.__body

    @body.setter
    def body(self, value):
        if not isinstance(value, (StreamBodyPipe, MemoryBodyPipe)):
            value = BodyPipe(value or [])

        if isinstance(self.__body, StreamBodyPipe):
            self.__body.consume()
        self.__body = value

    def __str__(self):
        if self.is_request:
            field = self.request_line
        else:
            field = self.status_line

        return '\r\n'.join([' '.join(map(str, field)), str(self.headers)])

    @cached_property
    def is_request(self):
        return not self.is_response

    @cached_property
    def is_response(self):
        return isinstance(self, HTTPResponse)


class HTTPRequest(HTTPMessage):
    def __init__(self, request_line=None, *args, **kwargs):
        self.request_line = request_line or RequestLine('GET', '/', 'HTTP/1.1')
        super(HTTPRequest, self).__init__(*args, **kwargs)

    @classmethod
    def from_parser(cls, parser):
        assert not isinstance(parser, ICAPRequestParser)
        assert parser.is_request
        return cls(parser.sline, parser.headers, parser.stream)


class HTTPResponse(HTTPMessage):
    def __init__(self, status_line=None, *args, **kwargs):
        super(HTTPResponse, self).__init__(*args, **kwargs)
        self.status_line = status_line or StatusLine('HTTP/1.1', 200, 'OK')

    @classmethod
    def from_parser(cls, parser):
        assert not isinstance(parser, ICAPRequestParser)
        assert parser.is_response
        return cls(parser.sline, parser.headers, parser.stream)


def BodyPipe(source):
    """Factory function that returns an instance of :class:`MemoryBodyPipe` or
    :class:`StreamBodyPipe`, depending on the input.
    """
    if hasattr(source, 'readline') and hasattr(source, 'read'):
        return StreamBodyPipe(source)
    return MemoryBodyPipe(source or [])


class MemoryBodyPipe(list):
    """An iterator over in-memory objects, e.g. a list, a string,
    or a generator.
    """
    def __init__(self, value):
        self.consumed = True

        if isinstance(value, str):
            value = [BodyPart(value, '')]
        elif isinstance(value, BodyPart):
            value = [value]

        try:
            iter(value)
        except TypeError:
            raise
        else:
            chunks = []
            for v in value:
                if not isinstance(v, BodyPart):
                    v = BodyPart(v, '')
                chunks.append(v)
            chunks = chunks

        super(MemoryBodyPipe, self).__init__(chunks)


class StreamBodyPipe(object):
    """An iterator over a stream, e.g. StringIO or a file."""
    def __init__(self, source):
        self.chunks = []
        self.consumed = False
        self.stream = source

    def __iter__(self):
        chunks = self.chunks

        if self.consumed:
            for chunk in chunks:
                yield chunk
            return

        while True:
            line = self.stream.readline().strip()
            try:
                size, header = line.split(';', 1)
            except ValueError:
                size = line
                header = ''

            # needs support for trailers
            size = int(size, 16)
            if size:
                # FIXME: non-crlf-endings
                data = self.stream.read(size+2)  # +2 for CRLF
                # FIXME: non-crlf-endings
                chunk = BodyPart(data[:-2], header)
                chunks.append(chunk)
                yield chunk
            else:
                # end of stream, get rid of trailing newline
                self.stream.readline()
                self.consumed = True
                return

    def consume(self):
        if not self.consumed:
            for chunk in self:
                pass
            self.consumed = True
        assert self.consumed

    def __bool__(self):
        self.consume()
        return bool(self.chunks)

    def __len__(self):
        self.consume()
        return len(self.chunks)


class Session(dict):
    """In memory storage between HTTP requests and responses."""
    sessions = {}

    @classmethod
    def from_request(cls, request):
        if 'X-Session-Id' in request.headers:
            session_id = request.headers['X-Session-Id']
        else:
            # FIXME: This needs a LOT of work.
            # It should probably be a hash of request line, Host and Cookies
            # headers.
            if request.is_reqmod:
                session_id = hash(str(request.http.headers))
            else:
                session_id = hash(str(request.http.request_headers))

        if session_id in cls.sessions:
            return cls.sessions[session_id]

        session = cls.sessions[session_id] = Session(session_id=session_id)
        session.populate(request)
        return session

    def finished(self):
        self.sessions.pop(self['session_id'], None)

    def populate(self, request):
        if isinstance(request.http, HTTPResponse):
            url = request.http.request_headers.get('Host', '') + request.http.request_line.uri
            url = urlparse.urlparse(url)
        else:
            url = request.http.headers.get('Host', '') + request.http.request_line.uri
            url = urlparse.urlparse(url)

        self['url'] = url
