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


class DomainCriteria(RegexCriteria):
    """Criteria that processes requests based on the domain.

    Supports globbing, e.g. "*google.com" matches "www.google.com", and
    "go?gle.com" matches "goggle.com" and "google.com".
    """
    priority = 2

    def __init__(self, *domains):
        domains_as_regexes = (s.replace('*', '.*').replace('?', '.')
                              for s in domains)
        domain_re = '^(%s)$' % '|'.join(domains_as_regexes)
        super(DomainCriteria, self).__init__(domain_re)

    def __call__(self, request):
        if request.is_reqmod:
            headers = request.http.headers
        else:
            headers = request.http.request_headers

        r = bool(self.regex.match(headers.get('Host', '')))
        return r


class AlwaysCriteria(BaseCriteria):
    """Criteria that matches 100% of the time.

    If you want to use this, just decorate a handler with
    :func:`icap.server.Server.handler` without any arguments.

    """
    priority = 5

    def __call__(self, request):
        return True
