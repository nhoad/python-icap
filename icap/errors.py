response_codes= {
    100: 'Continue',
    200: 'OK',
    204: 'No modifications needed',
    400: 'Bad request',
    404: 'ICAP Service not found',
    408: 'Request timeout',
    405: 'Method not allowed for service',
    418: 'Bad composition',
    500: 'Server error',
    501: 'Method not implemented',
    503: 'Service overloaded',
    505: 'ICAP version not supported',
}


def abort(code):
    """Utility function for quick-aborting a transaction."""
    raise ICAPAbort(code)


class ICAPAbort(Exception):
    """Used to quick abort a session with a given response code.

    When handled in :class:`Service`, exceptions of this nature will be sent
    back to the client with the ICAP status code that was raised. See
    :func:`utils.catch_all_errors` for details.

    This exception should not be used directly. :func:`utils.abort` should be
    used instead.
    """
    def __init__(self, status_code, message=None):
        if message is None:
            message = "'%d %s' was raised" % (status_code, response_codes.get(
                status_code, str(status_code)))

        super(ICAPAbort, self).__init__(message)
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
        super(InvalidEncapsulatedHeadersError, self).__init__(message)


class MalformedRequestError(Exception):
    """Represents an invalid request/status line."""
    pass
