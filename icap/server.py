"""
Misc function and classes for running the ICAP server.
"""
import asyncio
import logging
import signal
import uuid

from .criteria import sort_handlers

__all__ = [
    'hooks',
    'run',
    'stop',
]


log = logging.getLogger(__name__)


class Hooks(dict):
    """Dispatch class for providing hooks at certain parts of the ICAP
    transaction.

    Used like so:

    >>> from icap import hooks
    >>> @hooks('options_headers')
    >>> def extra_headers():
    ...     return {'new': 'headers'}

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
            except Exception as e:
                log.error("Error calling hook '%s'", name, exc_info=True)
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
            return func
        return wrapped


hooks = Hooks()

_server = None
_fallback_is_tag = uuid.uuid4().hex


@hooks('is_tag', default=_fallback_is_tag)
def is_tag_hook(request):
    """Fallback hook for ISTag, a required ICAP header. This header may be used
    by ICAP clients for determining a cache "cookie" of a response.

    """
    return _fallback_is_tag


def is_tag(request):
    """Return the quoted ISTag header value to be used for the response of
    a given request, truncated to 32 bytes.

    You don't need to use this directly.
    """
    return '"%s"' % hooks['is_tag'](request)[:32]


def signal_handlers():
    """Install handlers for SIGTERM, SIGINT, and SIGBREAK to stop the server
    gracefully.

    To disable this behaviour, pass install_signal_handlers=False to
    `~icap.server.run`.

    """
    loop = asyncio.get_event_loop()

    loop.add_signal_handler(signal.SIGTERM, stop)
    loop.add_signal_handler(signal.SIGINT, stop)

    if hasattr(signal, "SIGBREAK"):
        loop.add_signal_handler(signal.SIGBREAK, stop)


def run(host='127.0.0.1', port=1334, *, install_signal_handlers=True,
        factory_class=None, **kwargs):
    """Run the ICAP server.

    Keyword arguments:
        ``host`` - the interface to use. Defaults to listening locally only.
        ``port`` - the port to listen on.
        ``factory_class`` - the callable to use for creating new protocols.
        Defaults to `~icap.asyncio.ICAPProtocolFactory`.
        ``install_signal_handlers`` - install signal handlers for graceful
        shutdown. See `~icap.server.signal_handlers`.

    Any other keyword arguments will be passed to ``factory_class`` before
    starting the server. See `~icap.asyncio.ICAPProtocolFactory` for
    accepted values.

    """
    global _server
    assert _server is None

    if factory_class is None:
        from .asyncio import ICAPProtocolFactory
        factory_class = ICAPProtocolFactory

    sort_handlers()

    if install_signal_handlers:
        signal_handlers()

    factory = factory_class(**kwargs)

    loop = asyncio.get_event_loop()
    f = loop.create_server(factory, host, port)
    _server = loop.run_until_complete(f)

    loop.run_until_complete(_server.wait_closed())


def stop():
    """Stop the server. Assumes it is already running."""
    global _server
    if _server is None:
        return
    _server.close()
    _server = None
