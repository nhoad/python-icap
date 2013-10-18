import urlparse

from cStringIO import StringIO
from collections import namedtuple, OrderedDict
from types import GeneratorType

from werkzeug import cached_property, http_date

from .errors import (
    InvalidEncapsulatedHeadersError,
    MalformedRequestError,
    abort,
    response_codes)

from .utils import (dump_encapsulated_field, parse_encapsulated_field,
                    convert_offsets_to_sizes)

# who could resist a class name like this?
BodyPart = namedtuple('BodyPart', 'content header')
RequestLine = namedtuple('RequestLine', 'method uri version')
StatusLine = namedtuple('StatusLine', 'version code reason')


class ParseState(object):
    empty = 1
    started = 2
    body_started = 3
    body_ended = 4


class HeadersDict(OrderedDict):
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
        return OrderedDict.__getitem__(self, key.lower())[0][1]

    def get(self, key, default=None):
        try:
            return self.__getitem__(key)
        except KeyError:
            return default

    def getlist(self, key, default=list):
        try:
            return [v for k, v in OrderedDict.__getitem__(self, key.lower())]
        except KeyError:
            return default()

    def replace(self, key, value):
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
        if not self:
            return ''

        s = '\r\n'.join(
            ': '.join(v) for k in self
            for v in OrderedDict.__getitem__(self, k)
        ) + '\r\n'

        return s


class ChunkedMessage(object):
    def __init__(self):
        self.sline = None
        self.headers = HeadersDict()
        self.state = ParseState.empty
        self.chunks = []

    def started(self, set=False):
        if set:
            self.state = ParseState.started
        return self.state != ParseState.empty

    def headers_complete(self, set=False):
        if set:
            self.state = ParseState.body_started
        return self.state > ParseState.started

    def complete(self, set=False):
        if set:
            self.state = ParseState.body_ended
        return self.state == ParseState.body_ended

    def __str__(self):
        return '\r\n'.join([' '.join(map(str, self.sline)), str(self.headers)])

    def __iter__(self):
        chunks = self.chunks

        if self.complete():
            for chunk in chunks:
                yield chunk
            return

        while not self.complete():
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
                self.complete(True)
                # end of stream, get rid of trailing newline
                self.stream.readline()

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

    def set_payload(self, payload):
        for chunk in self:
            pass

        if isinstance(payload, basestring):
            payload = [BodyPart(payload, '')]
        elif isinstance(payload, (list, GeneratorType)):
            payload = [BodyPart(p, '') for p in payload]
        self.chunks = payload

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
        return isinstance(self.sline, RequestLine)

    @cached_property
    def is_response(self):
        return not self.is_request

    @cached_property
    def request_line(self):
        '''Request line of the HTTP/ICAP request object, e.g. 'GET / HTTP/1.1'

        This is a convenience attribute that points at `self.sline`.

        Will raise AttributeError if the request object is not a request.
        '''

        if self.is_request:
            return self.sline
        raise AttributeError("%r object has no attribute 'request_line'"
                             % (self.__class__.__name__))

    @cached_property
    def status_line(self):
        '''Request line of the HTTP/ICAP request object, e.g. 'HTTP/1.1 200 OK'

        This is a convenience attribute that points at `self.sline`.

        Will raise AttributeError if the request object is not a response.
        '''

        if self.is_response:
            return self.sline
        raise AttributeError("%r object has no attribute 'status_line'"
                             % (self.__class__.__name__))


class ICAPRequest(ChunkedMessage):
    @classmethod
    def from_stream(cls, stream):
        self = super(ICAPRequest, cls).from_stream(stream)

        # handle a short read.
        if self is None:
            return self

        assert self.headers_complete()

        parts = convert_offsets_to_sizes(self.encapsulated_header)

        if self.is_respmod:
            if 'req-hdr' in parts:
                data = self.stream.read(parts['req-hdr'])
                req = ChunkedMessage.from_bytes(data)
                req_sline = req.sline
                req_headers = req.headers
            else:
                req_sline = None
                req_headers = HeadersDict()

        missing_headers = ((self.is_reqmod and 'req-hdr' not in parts) or
                           (self.is_respmod and 'res-hdr' not in parts))

        if missing_headers:
            m = ChunkedMessage()
            m.headers_complete(True)
            m.stream = self.stream
        elif self.is_options and set(parts.keys()) == {'null-body'}:
            # TODO: is this the right thing to do?
            m = ChunkedMessage()
        else:
            # NOTE: As it stands, we don't actually use req-hdr or res-hdr for
            # reading the correct amount for headers here, but rely on the
            # ChunkedMessage parsing.
            m = ChunkedMessage.from_stream(self.stream)

        self.http = m

        if self.is_respmod:
            m.request_line = req_sline
            m.request_headers = req_headers

        if 'null-body' in parts:
            m.complete(True)

        return self

    def handle_status_line(self, sline):
        super(ICAPRequest, self).handle_status_line(sline)

        if self.sline.method not in {'OPTIONS', 'REQMOD', 'RESPMOD'}:
            abort(501)

    def __iter__(self):
        for chunk in self.http:
            yield chunk

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
    def allow_204(self):
        return '204' in self.headers.get('allow', '')

    @cached_property
    def is_reqmod(self):
        return self.is_request and self.sline.method == 'REQMOD'

    @cached_property
    def is_respmod(self):
        return self.is_request and self.sline.method == 'RESPMOD'

    @cached_property
    def is_options(self):
        return self.is_request and self.sline.method == 'OPTIONS'


class ICAPResponse(object):
    def __init__(self, status_line=None, headers=None, http=None, is_options=False):
        self.status_line = status_line or StatusLine('ICAP/1.0', 200, 'OK')
        self.http = http or ChunkedMessage()
        self.headers = headers or HeadersDict()
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

    @classmethod
    def from_request(cls, request):
        status_line = StatusLine('ICAP/1.0', 200, 'OK')
        self = cls(status_line, http=request.http)
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
        stream.flush()

        self.write_chunks(stream, self.http.chunks)
        stream.flush()

    def set_required_headers(self, is_tag):
        """Sets headers required for the ICAP response."""
        self.headers['Date'] = http_date()
        self.headers['ISTag'] = is_tag

    def write_chunks(self, stream, chunks):
        """Write out each chunk to the given stream."""
        for chunk in self.http.chunks:
            s = chunk.content
            n = hex(len(s))[2:]  # strip off leading 0x

            header = chunk.header.strip()
            if header and header != 'ieof':
                header = '%s; %s' % (n, header)
            else:
                header = n

            stream.write(header+'\r\n')
            stream.write(s+'\r\n')
            stream.flush()

        stream.write('0\r\n')

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
            elif http.is_response:
                encapsulated = OrderedDict([('res-hdr', 0)])
                body_key = 'res-body'

            if not http.chunks:
                body_key = 'null-body'

            encapsulated[body_key] = len(http_preamble)

        self.headers['Encapsulated'] = dump_encapsulated_field(encapsulated)

        return http_preamble


class HTTPRequest(object):
    def __init__(self, request_line=None, headers=None, body=None):
        # really not comfortable with that default...
        self.request_line = request_line or RequestLine('GET', '/', 'HTTP/1.1')
        if isinstance(body, str) or body is None:
            body = [body]

        body = [BodyPart(b, '') for b in body if b]
        self.chunks = body or []
        self.headers = headers or HeadersDict()

        self.is_request = True
        self.is_response = False

    def __str__(self):
        return '\r\n'.join([' '.join(map(str, self.request_line)), str(self.headers)])


class HTTPResponse(object):
    def __init__(self, status_line=None, headers=None, body=None):
        self.status_line = status_line or StatusLine('HTTP/1.1', 200, 'OK')
        if isinstance(body, str) or body is None:
            body = [body]

        body = [BodyPart(b, '') for b in body]
        self.chunks = body or []
        self.headers = headers or HeadersDict()

        self.is_request = False
        self.is_response = True

    def __str__(self):
        return '\r\n'.join([' '.join(map(str, self.status_line)), str(self.headers)])


def parse_start_line(sline):
    """Parse the first line from an HTTP/ICAP message and return an instance of
    StatusLine or RequestLine.

    Will raise MalformedRequestError if there was an error during parsing.
    """
    try:
        method, uri, version = parts = sline.split(' ', 2)
    except ValueError:
        raise MalformedRequestError

    if method.upper().startswith(('HTTP', 'ICAP')):
        version, code, reason = parts
        try:
            return StatusLine(version.upper(), int(code), reason)
        except ValueError:
            raise MalformedRequestError
    else:
        return RequestLine(method.upper(), uri, version.upper())


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
        if request.http.is_response:
            url = request.http.request_headers.get('Host', '') + request.http.request_line.uri
            url = urlparse.urlparse(url)
        else:
            url = request.http.headers.get('Host', '') + request.http.request_line.uri
            url = urlparse.urlparse(url)

        self['url'] = url
