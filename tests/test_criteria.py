import urllib.parse

from mock import MagicMock

from icap import RegexCriteria, DomainCriteria, handler
from icap.criteria import _HANDLERS, sort_handlers, get_handler


class FakeRequest(object):
    def __init__(self, url):
        self.session = {
            'url': urllib.parse.urlparse(url),
        }
        self.http = MagicMock()
        self.http.headers.get.return_value = self.session['url'].netloc

        self.is_reqmod = True


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

