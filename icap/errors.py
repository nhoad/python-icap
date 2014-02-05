http_response_codes = {
    100: 'Continue',
    101: 'Switching Protocols',
    200: 'OK',
    201: 'Created',
    202: 'Accepted',
    203: 'Non-Authoritative Information',
    204: 'No Content',
    205: 'Reset Content',
    206: 'Partial Content',
    300: 'Multiple Choices',
    301: 'Moved Permanently',
    302: 'Found',
    303: 'See Other',
    304: 'Not Modified',
    305: 'Use Proxy',
    306: '(Unused)',
    307: 'Temporary Redirect',
    400: 'Bad Request',
    401: 'Unauthorized',
    402: 'Payment Required',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    406: 'Not Acceptable',
    407: 'Proxy Authentication Required',
    408: 'Request Timeout',
    409: 'Conflict',
    410: 'Gone',
    411: 'Length Required',
    412: 'Precondition Failed',
    413: 'Request Entity Too Large',
    414: 'Request-URI Too Long',
    415: 'Unsupported Media Type',
    416: 'Requested Range Not Satisfiable',
    417: 'Expectation Failed',
    500: 'Internal Server Error',
    501: 'Not Implemented',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
    505: 'HTTP Version Not Supported',
}

icap_response_codes = dict(http_response_codes)
icap_response_codes.update({
    204: 'No Modifications Needed',
    404: 'ICAP Service Not Found',
    405: 'Method Not Allowed For Service',
    418: 'Bad Composition',
    501: 'Method Not Implemented',
    503: 'Service Overloaded',
    505: 'ICAP Version Not Supported',
})


def abort(code):
    """Utility function for quick-aborting a transaction.

    See :exc:`ICAPAbort` for more details.
    """
    raise ICAPAbort(code)


class ICAPAbort(Exception):
    """Used to quick abort a session with a given response code.

    When handled in :class:`icap.server.Server`, exceptions of this nature will be sent
    back to the client with the ICAP status code that was raised.

    This exception should not be used directly. :func:`abort` should be used
    instead.
    """
    def __init__(self, status_code, message=None):
        if message is None:
            message = "'%d %s' was raised" % (
                status_code, icap_response_codes[status_code])

        super().__init__(message)
        self.status_code = status_code


class InvalidEncapsulatedHeadersError(Exception):
    """Represents a bug in an ICAP client, or the icap package, sending through
    a malformed Encapsulated header.

    If this is raised when parsing a request from a client, notify the
    maintainer of that client.

    If this is raised when serializing a response to a client, notify the
    maintainer of this package.
    """

    def __init__(self, raw_field):
        self.raw_field = raw_field

        message = ("Encapsulated field does not comply with RFC3507: %s"
                   % raw_field)
        super().__init__(message)


class MalformedRequestError(Exception):
    """Represents an invalid request/status line."""
    pass
