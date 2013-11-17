import fnmatch
import functools
import re
import urllib.parse

from collections import defaultdict

from .errors import abort

_HANDLERS = defaultdict(list)


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


def get_handler(request, strict_when_missing_service=False):
    uri = request.request_line.uri
    path = uri.path
    services = _HANDLERS.get(path)

    if not services:
        # RFC3507 says we should abort with 404 if there are no handlers at
        # a given resource - this is fine except when the client (Squid, in
        # this case) relays ICAP 404 responses to the client as internal
        # errors.
        abort(404 if strict_when_missing_service or request.is_options else 204)

    for criteria, handler, raw in services:
        if criteria(request):
            return handler, raw

    if request.is_options:
        handler = lambda req: None
        return handler, False

    abort(204)


def handler(criteria=None, name='', raw=False):
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


