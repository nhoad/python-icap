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
