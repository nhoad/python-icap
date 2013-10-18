import urlparse

from mock import MagicMock

from icap import RegexCriteria, DomainCriteria


class FakeRequest(object):
    def __init__(self, url):
        self.session = {
            'url': urlparse.urlparse(url),
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
