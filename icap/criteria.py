import fnmatch
import functools
import re
import urllib.parse

from collections import defaultdict

from .errors import abort

_HANDLERS = defaultdict(list)


__all__ = [
    'BaseCriteria',
    'ContentTypeCriteria',
    'DomainCriteria',
    'HTTPRequestCriteria',
    'HTTPResponseCriteria',
    'HeaderCriteria',
    'MethodCriteria',
    'RegexCriteria',
    'StatusCodeCriteria',
    'handler',
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

    def __and__(self, other):
        return AllOfCriteria(self, other)

    def __or__(self, other):
        return AnyOfCriteria(self, other)


class AnyOfCriteria(BaseCriteria):
    """Criteria that matches only if any given child criteria match."""

    def __init__(self, *criteria):
        super().__init__()
        self.criteria = criteria

    def __call__(self, request):
        return any(c(request) for c in self.criteria)

    def __str__(self):
        return '<%s (%s)>' % (self.__class__.__name__, ', '.join(map(str, self.criteria)))


class AllOfCriteria(BaseCriteria):
    """Criteria that matches only if all given child criteria match."""

    def __init__(self, *criteria):
        super().__init__()
        self.criteria = criteria

    def __call__(self, request):
        return all(c(request) for c in self.criteria)

    def __str__(self):
        return '<%s (%s)>' % (self.__class__.__name__, ', '.join(map(str, self.criteria)))


class RegexCriteria(BaseCriteria):
    """Criteria that processes requests based on the URL, by a regex."""
    priority = 3

    def __init__(self, regex):
        super().__init__()
        self.regex = re.compile(regex)

    def __call__(self, request):
        url = urllib.parse.urlunparse(request.session['url'])
        return bool(self.regex.match(url))

    def __str__(self):
        return '<%s (%r)>' % (self.__class__.__name__, self.regex.pattern)


class DomainCriteria(BaseCriteria):
    """Criteria that processes requests based on the domain.

    Supports globbing, e.g. "*google.com" matches "www.google.com", and
    "go?gle.com" matches "goggle.com" and "google.com".
    """
    priority = 2

    def __init__(self, *domains):
        super().__init__()
        self.domains = domains

    def __call__(self, request):
        if request.is_reqmod:
            headers = request.http.headers
        else:
            headers = request.http.request_headers

        host = headers.get('Host', '')
        match = functools.partial(fnmatch.fnmatch, host)

        return any(match(pattern) for pattern in self.domains)

    def __str__(self):
        return '<%s (%r)>' % (self.__class__.__name__, ', '.join(self.domains))


class ContentTypeCriteria(BaseCriteria):
    """Criteria that matches responses based on the Content-Type header."""

    priority = 2

    def __init__(self, *content_types):
        super().__init__()
        self.content_types = content_types

     def __call__(self, request):
        headers = request.http.headers
        content_type = headers.get('content-type', '').split(';')[0]

        return content_type in self.content_types

    def __str__(self):
        return '<%s (%r)>' % (self.__class__.__name__, ', '.join(self.content_types))


class MethodCriteria(BaseCriteria):
    """Criteria that matches on the method of the encapsulated HTTP request."""

    def __init__(self, *methods):
        self.methods = {s.upper() for s in methods}

    def __call__(self, request):
        return request.http.request_line.method in self.methods


class HTTPRequestCriteria(BaseCriteria):
    """Criteria that matches if the request is a REQMOD."""
    def __call__(self, request):
        return request.is_reqmod


class HTTPResponseCriteria(BaseCriteria):
    """Criteria that matches if the request is a RESPMOD."""
    def __call__(self, request):
        return request.is_respmod


class StatusCodeCriteria(HTTPResponseCriteria):
    """Criteria that matches on the status code of the encapsulated HTTP response.

    Never matches on HTTP requests.

    """

    def __init__(self, *status_codes):
        self.status_codes = status_codes

    def __call__(self, request):
        http = request.http

        # super isn't callable! The horror.
        return (super().__call__(request) and
                http.status_line.code in self.status_codes)


class HeaderCriteria(BaseCriteria):
    """Criteria that matches on the presence of a header, optionally matching
    on the value of the header.

    """
    def __init__(self, key, *values):
        self.key = key.lower()
        self.values = set(values)
        self.check_values = bool(values)

    def __call__(self, request):
        values = request.http.headers.getlist(self.key)

        if values:
            if self.check_values:
                return bool(self.values & set(values))
            else:
                return True

        return False


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

    if request.is_options:
        return None, True

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
        orig_handler = handler
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
        return orig_handler

    return inner
