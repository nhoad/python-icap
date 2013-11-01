import fnmatch
import functools
import re
import urlparse


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
        url = urlparse.urlunparse(request.session['url'])
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
