import urlparse

from mock import MagicMock

from icap import RegexService, DomainService, BaseService


class FakeRequest(object):
    def __init__(self, url):
        self.session = {
            'url': urlparse.urlparse(url),
        }


class DummyService(BaseService):
    pass


class TestDomainService(object):
    def test_normal_domain(self):
        r = DomainService('google.com')

        assert r.can_handle(FakeRequest('http://google.com'))
        assert not r.can_handle(FakeRequest('http://google.com.au'))

    def test_start_glob(self):
        r = DomainService('*google.com')
        assert r.can_handle(FakeRequest('http://google.com'))
        assert r.can_handle(FakeRequest('http://sub.google.com'))
        assert not r.can_handle(FakeRequest('http://google.com.au'))

    def test_both_glob(self):
        r = DomainService('*google.com*')
        assert r.can_handle(FakeRequest('http://google.com'))
        assert r.can_handle(FakeRequest('http://sub.google.com'))
        assert r.can_handle(FakeRequest('http://google.com.au'))
        assert not r.can_handle(FakeRequest('http://googleg.com.au'))

    def test_single_char(self):
        r = DomainService('go?gle.com')
        assert r.can_handle(FakeRequest('http://google.com'))
        assert r.can_handle(FakeRequest('http://goggle.com'))
        assert not r.can_handle(FakeRequest('http://giggle.com'))


def test_RegexService():
    r = RegexService(r'http://google.com$')
    assert r.can_handle(FakeRequest('http://google.com'))
    assert not r.can_handle(FakeRequest('http://google.com.au'))

    r = RegexService(r'http://google.com.*foo')

    assert r.can_handle(FakeRequest('http://google.com.abcde.foo'))
    assert not r.can_handle(FakeRequest('https://google.com.abcde.foo'))

    r = RegexService(r'http://google.com[1-4]')
    assert r.can_handle(FakeRequest('http://google.com1'))
    assert r.can_handle(FakeRequest('http://google.com2'))
    assert r.can_handle(FakeRequest('http://google.com3'))
    assert r.can_handle(FakeRequest('http://google.com4'))
    assert not r.can_handle(FakeRequest('http://google.com5'))


class TestBaseService(object):
    def test_handle_reqmod(self):
        s = DummyService()

        @s.handler
        def reqmod(self, *args):
            return 'from reqmod'

        assert s.handle(MagicMock()) == 'from reqmod'

    def test_handle_respmod(self):
        s = DummyService()

        @s.handler
        def respmod(self, *args):
            return 'from respmod'

        assert s.handle(MagicMock(is_reqmod=False)) == 'from respmod'

    def test_handle_both(self):
        s = DummyService()

        @s.handler
        def respmod(self, *args):
            return 'from respmod'

        @s.handler
        def reqmod(self, *args):
            return 'from reqmod'

        assert s.handle(MagicMock(is_reqmod=False)) == 'from respmod'
        assert s.handle(MagicMock(is_reqmod=True)) == 'from reqmod'

    def test_handle_both_weirdo(self):
        s = DummyService()

        @s.handler
        def reqmod_and_respmod(self, *args):
            return 'from reqmod or respmod'

        assert s.handle(MagicMock(is_reqmod=False)) == 'from reqmod or respmod'

    def test_handle_class(self):
        s = DummyService()

        @s.handler
        class Foo(object):
            def reqmod(self, message):
                assert message == 'http reqmod'

            def respmod(self, message):
                assert message == 'http respmod'

        s.handle(MagicMock(http='http reqmod'))
        s.handle(MagicMock(is_reqmod=False, http='http respmod'))

    def test_handle_raw(self):
        s = DummyService()

        @s.handler(raw=True)
        def reqmod_and_respmod(message):
            assert message != 'http'

        s.handle(MagicMock(http='http'))
        s.handle(MagicMock(is_reqmod=False, http='http'))
