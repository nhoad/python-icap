import urllib.parse

from mock import MagicMock

from icap import (
    RegexCriteria, DomainCriteria, handler, ContentTypeCriteria,
    MethodCriteria, HeaderCriteria, HeadersDict, HTTPRequestCriteria,
    HTTPResponseCriteria, StatusCodeCriteria)
from icap.criteria import _HANDLERS, sort_handlers, get_handler


class FakeRequest(object):
    def __init__(self, url, method='GET', headers=()):
        headers = dict(headers)
        self.session = {
            'url': urllib.parse.urlparse(url),
        }
        self.http = MagicMock()
        self.http.request_line.method = method
        self.http.headers = HeadersDict([
            ('Host', self.session['url'].netloc),
        ])

        for key, value in headers.items():
            self.http.headers[key] = value

        self.is_reqmod = True


def test_AnyOfCriteria():
    c = DomainCriteria('google.com') | RegexCriteria('.*gbogle.c[ao]m.*')

    assert c(FakeRequest('http://google.com'))
    assert c(FakeRequest('http://gbogle.cam'))
    assert c(FakeRequest('http://gbogle.com'))
    assert not c(FakeRequest('http://twitter.com'))


def test_AllOfCriteria():
    c = DomainCriteria('google.com') & RegexCriteria('https://')

    assert not c(FakeRequest('http://google.com'))
    assert c(FakeRequest('https://google.com'))


def test_HTTPRequestCriteria():
    a = HTTPRequestCriteria()

    assert a(FakeRequest('foo'))

    r = FakeRequest('foo')
    r.is_reqmod = False

    assert not a(r)


def test_HTTPResponseCriteria():
    a = HTTPResponseCriteria()

    r = FakeRequest('foo')
    r.is_respmod = True

    assert a(r)

    r.is_respmod = False
    assert not a(r)


class TestDomainCriteria(object):
    def test_normal_domain(self):
        r = DomainCriteria('google.com')

        assert r(FakeRequest('http://google.com'))
        assert not r(FakeRequest('http://google.com.au'))

    def test_start_glob(self):
        r = DomainCriteria('*google.com')
        assert r(FakeRequest('http://google.com'))
        assert r(FakeRequest('http://sub.google.com'))
        assert not r(FakeRequest('http://google.com.au'))

    def test_both_glob(self):
        r = DomainCriteria('*google.com*')
        assert r(FakeRequest('http://google.com'))
        assert r(FakeRequest('http://sub.google.com'))
        assert r(FakeRequest('http://google.com.au'))
        assert not r(FakeRequest('http://googleg.com.au'))

    def test_single_char(self):
        r = DomainCriteria('go?gle.com')
        assert r(FakeRequest('http://google.com'))
        assert r(FakeRequest('http://goggle.com'))
        assert not r(FakeRequest('http://giggle.com'))

    def test_missing_host_header(self):
        request = MagicMock()

        def get(key, default):
            return default

        request.http.headers.get = get

        r = DomainCriteria('google.com')
        assert not r(request)


class TestContentTypeCriteria:
    def test_no_match_on_request(self):
        r = ContentTypeCriteria()
        assert not r(FakeRequest('foo'))

    def test_no_match_on_missing_content_type(self):
        r = ContentTypeCriteria()
        f = FakeRequest('foo')
        f.is_reqmod = False
        assert not r(f)

    def test_no_match_on_wrong_content_type(self):
        pass

    def test_match(self):
        f = FakeRequest('foo')
        f.is_reqmod = False
        r = ContentTypeCriteria('text/html')

        f.http.headers['Content-Type'] = 'text/html'

        assert r(f)


def test_RegexCriteria():
    r = RegexCriteria(r'http://google.com$')
    assert r(FakeRequest('http://google.com'))
    assert not r(FakeRequest('http://google.com.au'))

    r = RegexCriteria(r'http://google.com.*foo')

    assert r(FakeRequest('http://google.com.abcde.foo'))
    assert not r(FakeRequest('https://google.com.abcde.foo'))

    r = RegexCriteria(r'http://google.com[1-4]')
    assert r(FakeRequest('http://google.com1'))
    assert r(FakeRequest('http://google.com2'))
    assert r(FakeRequest('http://google.com3'))
    assert r(FakeRequest('http://google.com4'))
    assert not r(FakeRequest('http://google.com5'))


def test_sort_handlers():
    _HANDLERS.clear()

    _HANDLERS['foo'] = [
        (DomainCriteria('google.com'), None, None),
        (RegexCriteria('.*'), None, None),
    ]

    sort_handlers()

    first, second = _HANDLERS['foo']

    assert isinstance(first[0], RegexCriteria)
    assert isinstance(second[0], DomainCriteria)


def test_MethodCriteria():
    c = MethodCriteria('POST', 'GET')

    assert c(FakeRequest('foo', method='POST'))
    assert c(FakeRequest('foo', method='GET'))
    assert not c(FakeRequest('foo', method='PUT'))


def test_StatusCodeCriteria():
    a = StatusCodeCriteria(200, 201)

    r = FakeRequest('foo')
    r.is_respmod = False

    assert not a(r)

    r.is_respmod = True
    assert not a(r)

    r.http.status_line.code = 200
    assert a(r)

    r.http.status_line.code = 201
    assert a(r)

    r.http.status_line.code = 400
    assert not a(r)


def test_HeaderCriteria():
    a = HeaderCriteria('X-Forwarded-For')
    b = HeaderCriteria('X-Forwarded-For', 'blah')

    assert a(FakeRequest('foo', headers={'X-Forwarded-For': 'blah'}))
    assert not a(FakeRequest('foo'))

    assert b(FakeRequest('foo', headers={'X-Forwarded-For': 'blah'}))
    assert not b(FakeRequest('foo', headers={'X-Forwarded-For': 'blup'}))


class TestHandlers:
    def setup_method(self, method):
        _HANDLERS.clear()

    def test_handle_mapping(self):
        @handler(lambda *args: True, name='lamps')
        def reqmod(message):
            pass  # pragma: no cover

        @handler(lambda *args: True, name='blarg')
        def respmod(message):
            pass  # pragma: no cover

        print(list(_HANDLERS.keys()))

        mock_request = MagicMock(is_reqmod=True, is_options=False)
        mock_request.request_line.uri.path = '/lamps/reqmod'
        assert get_handler(mock_request)[0] == reqmod

        mock_request = MagicMock(is_reqmod=False, is_options=False)
        mock_request.request_line.uri.path = '/blarg/respmod'
        assert get_handler(mock_request)[0] == respmod

    def test_handle_reqmod(self):
        @handler(lambda *args: True)
        def reqmod(self, *args):
            pass  # pragma: no cover

        request = MagicMock(http='http', is_options=False)
        request.request_line.uri.path = '/reqmod'

        assert get_handler(request)[0] == reqmod

    def test_handle_respmod(self):
        @handler(lambda *args: True)
        def respmod(self, *args):
            pass  # pragma: no cover

        request = MagicMock(is_reqmod=False, http='http', is_options=False)
        request.request_line.uri.path = '/respmod'

        assert get_handler(request)[0] == respmod

    def test_handle_both(self):
        @handler(lambda *args: True)
        def respmod(self, *args):
            pass  # pragma: no cover

        @handler(lambda *args: True)
        def reqmod(self, *args):
            pass  # pragma: no cover

        request = MagicMock(is_reqmod=False, http='http', is_options=False)
        request.request_line.uri.path = '/respmod'
        assert get_handler(request)[0] == respmod

        request = MagicMock(http='http', is_options=False)
        request.request_line.uri.path = '/reqmod'
        assert get_handler(request)[0] == reqmod

    def test_handle_class(self):
        @handler(lambda *args: True)
        class Foo(object):
            def reqmod(self, message):
                pass  # pragma: no cover

            def respmod(self, message):
                pass  # pragma: no cover

        print(_HANDLERS)

        reqmod = MagicMock(http='http', is_options=False)
        respmod = MagicMock(is_reqmod=False, http='http', is_options=False)
        reqmod.request_line.uri.path = '/reqmod'
        respmod.request_line.uri.path = '/respmod'

        assert get_handler(reqmod)[0] == _HANDLERS['/reqmod'][0][1]
        assert get_handler(respmod)[0] == _HANDLERS['/respmod'][0][1]
        assert isinstance(Foo, type)

