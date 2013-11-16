import logging
import re
import signal
import socket
import time
import uuid

from collections import defaultdict

from .criteria import AlwaysCriteria
from .models import ICAPResponse, Session, HTTPMessage, StatusLine
from .serialization import Serializer
from .errors import abort, ICAPAbort, MalformedRequestError
from .parsing import ICAPRequestParser

log = logging.getLogger(__name__)


class Hooks(dict):
    """Dispatch class for providing hooks at certain parts of the ICAP
    transaction.

    Used on a server instance like so:

    >>> from icap.server import Server
    >>> server = Server()
    >>> @server.hooks('options_headers')
    >>> def extra_headers():
    ...     return {'new': 'headers'}


    Available hooks:
        options_headers:
            Return dictionary of additional headers to add to the OPTIONS
            response.

            arguments: None.

        is_tag:
            Return a string to be used for a custom ISTag header on the
            response. String will be sliced to maximum of 32 bytes.

            arguments: request object, may be None.

    """
    def __getitem__(self, name):
        """Return the callable hook matching *name*.

        Always returns a callable that won't raise an exception.

        """

        if name in self:
            func, default = dict.__getitem__(self, name)
        else:
            func = lambda *args: None
            default = None

        def safe_callable(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception:
                return default
        return safe_callable

    def __call__(self, name, default=None, override=False):
        """Register a hook function with *name*, and *default* return value.

        Unless *override* is True, then *default* will only be saved the for
        the first time. This is to ensure sane defaults are used in the event
        that an error occurs in the registered hook.

        """
        # we want to keep the original default, as it will be used if the new
        # one fails, e.g. for the ISTag header.
        if name in self and not override:
            _oldfunc, default = dict.__getitem__(self, name)

        def wrapped(func):
            self[name] = func, default
        return wrapped
