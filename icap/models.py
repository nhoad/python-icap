from urllib import urlencode
from urlparse import parse_qs, urlparse

from collections import namedtuple, OrderedDict

from werkzeug import cached_property

from .errors import (
    InvalidEncapsulatedHeadersError,
    MalformedRequestError,
    abort,
    icap_response_codes,
    http_response_codes)

from .parsing import ICAPRequestParser
from .serialization import bodypipe, StreamBodyPipe, MemoryBodyPipe


class RequestLine(namedtuple('RequestLine', 'method uri version')):
    """Parsed request line, e.g. GET / HTTP/1.1, or
    REQMOD / ICAP/1.1.

    Available attributes are ``method``, ``uri``, ``version`` and ``query``.

    This class is purposefully directly immutable. You may modify the
    attributes on the `uri` attribute all you want; they will be reserialized.

    You can replace attributes by constructing new instances from the old ones,
    like a namedtuple. For example:

    >>> from icap import RequestLine
    >>> RequestLine('GET', '/', 'HTTP/1.1')._replace(method='POST')
    RequestLine(method='POST', uri=ParseResult(scheme='', netloc='', path='/', params='', query={}, fragment=''), version='HTTP/1.1')

    But generally, try to restrict yourself to query parameter changes only,
    which don't involve this kludgery. It's generally poor form to change HTTP
    versions, and changing the method is very impolite.
    """
    __slots__ = ()

    # we're subclassing a tuple here, __new__ is necessary.
    def __new__(self, method, uri, version):
        uri = urlparse(uri)
        uri = uri._replace(query=parse_qs(uri.query))
        return super(RequestLine, self).__new__(self, method, uri, version)

    def __str__(self):
        method, uri, version = self
        uri = uri._replace(query=urlencode(uri.query, doseq=True)).geturl()
        return ' '.join([method, uri, version])

    @property
    def query(self):
        """Proxy attribute for ``self.uri.query``.

        Returns a reference, so modifications to the query via this property
        will be reserialised.

        """
        return self.uri.query


class StatusLine(namedtuple('StatusLine', 'version code reason')):
    """Parsed status line, e.g. HTTP/1.1 200 OK or ICAP/1.1 200 OK.

    This class is purposefully directly immutable.

    You can replace attributes by constructing new instances from the old ones,
    like a namedtuple. For example:

    >>> from icap import StatusLine
    >>> StatusLine('HTTP/1.1', '200', 'OK')._replace(version='ICAP/1.1')
    StatusLine(version='ICAP/1.1', code=200, reason='OK')

    But **don't do it without a good reason**. It's generally poor form to
    change these sorts of things.

    Instances can also be constructed without the ``reason`` attribute
    fulfilled. In these cases, it will be filled out from
    `icap.errors.icap_response_codes` or `icap.errors.http_response_codes`:

    >>> from icap import StatusLine
    >>> StatusLine('HTTP/1.1', '204')
    StatusLine(version='HTTP/1.1', code=204, reason='No Content')
    """
    __slots__ = ()

    def __new__(self, version, code, *args):
        code = int(code)
        if args:
            reason, = args
        elif version.startswith('HTTP'):
            reason = http_response_codes[code]
        else:
            reason = icap_response_codes[code]

        return super(StatusLine, self).__new__(self, version, code, reason)

    def __str__(self):
        return ' '.join(map(str, self))


class HeadersDict(OrderedDict):
    """Multivalue, case-aware dictionary type used for headers of requests and
    responses.

    """
    def __init__(self, items=()):
        OrderedDict.__init__(self)
        for key, value in items:
            self[key] = value

    def __setitem__(self, key, value):
        """Append``value`` to the list stored at ``key``, case insensitively.

        The case of ``key`` is preserved internally for later use.

        """
        lkey = key.lower()

        if lkey not in self:
            OrderedDict.__setitem__(self, lkey, [(key, value)])
        else:
            OrderedDict.__getitem__(self, lkey).append((key, value))

    def __getitem__(self, key):
        """Return the first value stored at ``key``."""
        return OrderedDict.__getitem__(self, key.lower())[0][1]

    def get(self, key, default=None):
        """Return the first value stored at ``key``. Return ``default`` if no
        value is present."""
        try:
            return self.__getitem__(key)
        except KeyError:
            return default

    def getlist(self, key, default=list):
        """Return all values stored at ``key``."""
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
    """Base ICAP class for generalising certain properties of both requests and
    responses.

    Should not be used directly - use `~icap.models.ICAPRequest` or
    `~icap.models.ICAPResponse` instead.

    """
    def __init__(self, headers=None, http=None):
        """If ``headers`` is not given, default to an empty instance of
        `~icap.models.HeadersDict`.

        ``http`` is the encapsulated HTTP message, either an instance of
        `~icap.models.ICAPRequest` or `~icap.models.ICAPResponse`.

        """
        self.headers = headers or HeadersDict()

        # really not comfortable with this default...
        self.http = http

    @cached_property
    def is_request(self):
        """Return True if this object is a request.

        This is just a shortcut for ``isinstance(self, ICAPRequest)``.

        """
        return isinstance(self, ICAPRequest)

    @cached_property
    def is_response(self):
        """Return True if this object is a response.

        This is just a shortcut for ``isinstance(self, ICAPResponse)``.

        """
        return isinstance(self, ICAPResponse)

    @cached_property
    def has_body(self):
        """Return True if this object has a payload."""
        if self.is_request and self.is_options and 'encapsulated' not in self.headers:
            return False
        return 'null-body' not in self.headers['encapsulated']


class ICAPRequest(ICAPMessage):
    """Representation of an ICAP request."""

    def __init__(self, request_line=None, *args, **kwargs):
        """If no ``request_line`` is given, a default of "UNKNOWN / ICAP/1.0"
        will be used.

        For all other available attributes, see `~icap.models.ICAPMessage`.

        """
        super(ICAPRequest, self).__init__(*args, **kwargs)
        self.request_line = request_line or RequestLine("UNKNOWN", "/", "ICAP/1.0")

    @classmethod
    def from_parser(cls, parser):
        """Return an instance of `~icap.models.ICAPRequest` from ``parser``.

        ``parser`` MUST be an instance of `~icap.parsing.ICAPRequestParser`.

        """
        assert isinstance(parser, ICAPRequestParser)

        self = cls(parser.sline, parser.headers, parser.http)
        return self

    @cached_property
    def allow_204(self):
        """Return True of the client supports a 204 response code."""
        # FIXME: this should parse the list.
        return ('204' in self.headers.get('allow', '') or 'preview' in self.headers)

    @cached_property
    def is_reqmod(self):
        """Return True if the current request is a REQMOD request."""
        return self.request_line.method == 'REQMOD'

    @cached_property
    def is_respmod(self):
        """Return True if the current request is a RESPMOD request."""
        return self.request_line.method == 'RESPMOD'

    @cached_property
    def is_options(self):
        """Return True if the current request is an OPTIONS request."""
        return self.request_line.method == 'OPTIONS'


class ICAPResponse(ICAPMessage):
    """Representation of an ICAP response."""

    def __init__(self, status_line=None, *args, **kwargs):
        """If no ``status_line`` is given, a default of "ICAP/1.0 200 OK" will
        be used.

        For all other available attributes, see `~icap.models.ICAPMessage`.

        """
        super(ICAPResponse, self).__init__(*args, **kwargs)
        self.status_line = status_line or StatusLine('ICAP/1.0', 200, 'OK')

    def __str__(self):
        return '\r\n'.join([' '.join(map(str, self.status_line)), str(self.headers)])

    @classmethod
    def from_error(cls, error):
        if isinstance(error, int):
            status_code = error
        else:
            status_code = error.status_code
        message = icap_response_codes[status_code]
        self = cls(StatusLine('ICAP/1.0', status_code, message))
        return self


class HTTPMessage(object):
    """Base HTTP class for generalising certain properties of both requests and
    responses.

    Should not be used directly - use `~icap.models.HTTPRequest` or
    `~icap.models.HTTPResponse` instead.

    """
    __body = None

    def __init__(self, headers=None, body=None):
        """If ``headers`` is not given, default to an empty instance of
        `~icap.models.HeadersDict`.

        ``body`` is an iterable of the payload of the HTTP message. It can be a
        stream, list of strings, a generator or a string.
        """
        self.headers = headers or HeadersDict()
        self.body = body

    @property
    def body(self):
        """Property for wrapping the body of a HTTP message.

        Setting this property will perform necessary wrapping to ensure it will
        be an instance of `~icap.serialization.StreamBodyPipe` or `icap.serialization.MemoryBodyPipe` when accessed.

        When setting this property, if the old value is a
        `~icap.serialization.StreamBodyPipe`, i.e. a container around an object
        with `readline()` and `read()` methods, the old stream will be consumed
        first.
        """
        return self.__body

    @body.setter
    def body(self, value):
        if not isinstance(value, (StreamBodyPipe, MemoryBodyPipe)):
            value = bodypipe(value or [])

        if isinstance(self.__body, StreamBodyPipe):
            self.__body.consume()
        self.__body = value

    def __str__(self):
        if self.is_request:
            field = self.request_line
        else:
            field = self.status_line

        return '\r\n'.join([str(field), str(self.headers)])

    @cached_property
    def is_request(self):
        """Return True if this object is a request.

        This is just a shortcut for ``isinstance(self, HTTPRequest)``.

        """
        return isinstance(self, HTTPRequest)

    @cached_property
    def is_response(self):
        """Return True if this object is a response.

        This is just a shortcut for ``isinstance(self, HTTPResponse)``.

        """
        return isinstance(self, HTTPResponse)


class HTTPRequest(HTTPMessage):
    """Representation of a HTTP request."""

    def __init__(self, request_line=None, *args, **kwargs):
        """If no ``request_line`` is given, a default of "GET / HTTP/1.1" will
        be used.

        For all other available attributes, see `~icap.models.HTTPMessage`.

        """
        self.request_line = request_line or RequestLine('GET', '/', 'HTTP/1.1')
        super(HTTPRequest, self).__init__(*args, **kwargs)

    @classmethod
    def from_parser(cls, parser):
        """Return an instance of `~icap.models.HTTPRequest` from ``parser``.

        ``parser`` MUST be an instance of `~icap.parsing.HTTPMessageParser`.

        """
        assert not isinstance(parser, ICAPRequestParser)
        assert parser.is_request
        return cls(parser.sline, parser.headers, parser.stream)


class HTTPResponse(HTTPMessage):
    """Representation of a HTTP response."""

    def __init__(self, status_line=None, *args, **kwargs):
        """Initialise a new `HTTPResponse` instance.

        If no ``status_line`` is given, a default of "HTTP/1.1 200 OK" will be
        used.

        For all other available attributes, see `~icap.models.HTTPMessage`.

        """
        super(HTTPResponse, self).__init__(*args, **kwargs)
        self.status_line = status_line or StatusLine('HTTP/1.1', 200, 'OK')

    @classmethod
    def from_parser(cls, parser):
        """Return an instance of `~icap.models.HTTPResponse` from ``parser``.

        ``parser`` MUST be an instance of `~icap.parsing.HTTPMessageParser`.

        """
        assert not isinstance(parser, ICAPRequestParser)
        assert parser.is_response
        return cls(parser.sline, parser.headers, parser.stream)


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
            url = request.http.request_line.uri
        else:
            url = request.http.request_line.uri

        self['url'] = url
