from cStringIO import StringIO
from collections import namedtuple, OrderedDict

from werkzeug import cached_property

from .utils import parse_encapsulated_field, convert_offsets_to_sizes

# who could resist a class name like this?
BodyPart = namedtuple('BodyPart', ['content', 'header'])
RequestLine = namedtuple('RequestLine', 'method uri version')
StatusLine = namedtuple('RequestLine', 'version code reason')


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


class ChunkedMessage(object):
    def __init__(self):
        self.sline = None
        self.headers = HeadersDict()
        self.state = ParseState.empty

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

    def __iter__(self):
        store_chunks = self.store_chunks
        chunks = self._chunks

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
                if store_chunks:
                    chunks.append(chunk)
                yield chunk
            else:
                self.complete(True)
                # end of stream, get rid of trailing newline
                self.stream.readline()

    @classmethod
    def from_kwargs(cls, store_chunks=False):
        message = cls()
        message.store_chunks = store_chunks
        message._chunks = []
        return message

    @classmethod
    def from_stream(cls, stream, **kwargs):
        message = cls.from_kwargs(**kwargs)

        complete = message.headers_complete
        while not complete():
            line = stream.readline()
            message._feed_line(line)

        assert message.headers_complete()

        message.stream = stream
        return message

    @classmethod
    def from_bytes(cls, bytes, **kwargs):
        return cls.from_stream(StringIO(bytes), **kwargs)

    def _feed_line(self, line):
        if not self.started():
            self.handle_status_line(line)
        elif not self.headers_complete():
            self.handle_header(line)

    def handle_status_line(self, sline):
        self.started(True)
        self.sline = parse_start_line(sline.strip())

    def handle_header(self, header):
        # FIXME: non-clrf-endings
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
    def from_stream(cls, stream, **kwargs):
        self = super(ICAPRequest, cls).from_stream(stream, **kwargs)

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
            m = ChunkedMessage.from_kwargs(store_chunks=not self.allow_204)
            m.headers_complete(True)
            m.stream = self.stream
        else:
            # NOTE: As it stands, we don't actually use req-hdr or res-hdr for
            # reading the correct amount for headers here, but rely on the
            # ChunkedMessage parsing.
            m = ChunkedMessage.from_stream(self.stream)

        self.encapsulated_message = m

        if self.is_respmod:
            m.request_sline = req_sline
            m.request_headers = req_headers

        if 'null-body' in parts:
            m.complete(True)

        return self

    def __iter__(self):
        for chunk in self.encapsulated_message:
            yield chunk

    @classmethod
    def from_kwargs(cls, **kwargs):
        return cls()

    @cached_property
    def encapsulated_header(self):
        # this MUST throw a key error. It's a required header.
        e = self.headers['encapsulated']
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


def parse_start_line(sline):
    method, uri, version = parts = sline.split(' ', 2)

    if method.upper().startswith(('HTTP', 'ICAP')):
        version, code, reason = parts
        return StatusLine(version.upper(), int(code), reason)
    else:
        return RequestLine(method.upper(), uri, version.upper())
