import fnmatch
import functools
import re
import urllib.parse

from collections import defaultdict

from .errors import abort

_HANDLERS = defaultdict(list)


__all__ = [
    'handler',
    'BaseCriteria',
    'RegexCriteria',
    'DomainCriteria',
]


@functools.total_ordering
class BaseCriteria(object):
    """Base Criteria class, provides a foundation for implementation of custom
    service handlers.
    """
    priority = 1

    def __lt__(self, other):
        return self.priority < other.priority

    def __call__(self, request):
        raise NotImplementedError()


class RegexCriteria(BaseCriteria):
    """Criteria that processes requests based on the URL, by a regex."""
    priority = 3

    def __init__(self, regex):
        super(RegexCriteria, self).__init__()
        self.regex = re.compile(regex)

    def __call__(self, request):
        url = urllib.parse.urlunparse(request.session['url'])
        return bool(self.regex.match(url))


class DomainCriteria(BaseCriteria):
    """Criteria that processes requests based on the domain.

    Supports globbing, e.g. "*google.com" matches "www.google.com", and
    "go?gle.com" matches "goggle.com" and "google.com".
    """
    priority = 2

    def __init__(self, *domains):
        super(DomainCriteria, self).__init__()
        self.domains = domains

    def __call__(self, request):
        if request.is_reqmod:
            headers = request.http.headers
        else:
            headers = request.http.request_headers

        host = headers.get('Host', '')
        match = functools.partial(fnmatch.fnmatch, host)

        return any(match(pattern) for pattern in self.domains)


class AlwaysCriteria(BaseCriteria):
    """Criteria that matches 100% of the time.

    If you want to use this, just decorate a handler with
    :func:`icap.server.Server.handler` without any arguments.

    """
    priority = 5

    def __call__(self, request):
        return True


def get_handler(request):
    """Return the handler for a given request, and whether it should be given
    the raw ICAP request.

    Will abort with the following codes in given conditions:

        404: no handlers at a given endpoint.
        204: there are handlers at a given endpoint, but none of them matched.

    """
    uri = request.request_line.uri
    path = uri.path
    services = _HANDLERS.get(path)

    if not services:
        # RFC3507 says we should abort with 404 if there are no handlers at
        # a given resource. The most common ICAP client, Squid, doesn't handle
        # this very well - it relays them to the client as internal errors.
        # Previously this was configurable to work around that, however it
        # actually means there's a configuration error on the admin's behalf,
        # so I've decided to make the 404 response mandatory.
        abort(404)

    for criteria, handler, raw in services:
        if criteria(request):
            return handler, raw

    abort(204)


def sort_handlers():
    """Sort _HANDLERS values by priority.

    You should not use this directly.

    """
    for key, items in _HANDLERS.items():
        _HANDLERS[key] = sorted(items, key=lambda f: f[0], reverse=True)


def handler(criteria=None, name='', raw=False):
    """Decorator to be used on functions/methods/classes intended to be used
    for handling request or response modifications.

    Keyword arguments:
        ``criteria`` - the criteria to be used for determining if the wrapped
                       callable should be used. If None, then will always be
                       used.
        ``name`` - subpath to use for matching, e.g. a name of 'foo' will
                   translate to a uri of ``/foo/reqmod`` or ``/foo/respmod``.
        ``raw`` - If True, the callable will receive an instance of
                  `~icap.models.ICAPRequest` instead of an instance of
                  `~icap.models.HTTPRequest` or `~icap.models.HTTPResponse`.

    """

    criteria = criteria or AlwaysCriteria()

    def inner(handler):
        if isinstance(handler, type):
            handler = handler()
            reqmod = getattr(handler, 'reqmod', None)
            respmod = getattr(handler, 'respmod', None)
        else:
            reqmod = handler if handler.__name__ == 'reqmod' else None
            respmod = handler if handler.__name__ == 'respmod' else None

        if reqmod:
            key = '/'.join([name, 'reqmod'])
            key = key if key.startswith('/') else '/%s' % key
            _HANDLERS[key].append((criteria, reqmod, raw))

        if respmod:
            key = '/'.join([name, 'respmod'])
            key = key if key.startswith('/') else '/%s' % key
            _HANDLERS[key].append((criteria, respmod, raw))
        return handler

    return inner
