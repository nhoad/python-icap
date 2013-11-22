
import pytest

from mock import MagicMock, patch

from icap import hooks
from icap.server import is_tag, _fallback_is_tag, stop, run


class TestISTag:
    def test_is_tag__valid_values(self):
        hooks('is_tag')(lambda request: 'a string')
        assert is_tag(None) == '"a string"'

    @pytest.mark.parametrize(('expected_is_tag', 'endswith'), [
        ('1'*31+'2', '2'),
        ('1'*30+'23', '3'),
        ('lamp', 'lamp'),
    ])
    def test_is_tag__maximum_length(self, expected_is_tag, endswith):
        hooks('is_tag')(lambda request: expected_is_tag)
        tag = is_tag(None)
        assert tag.endswith(endswith+'"')
        assert len(tag) <= 34

    def test_is_tag__error(self):
        @hooks('is_tag')
        def is_tag_bad(request):
            raise Exception('boom')

        assert is_tag(None) == '"%s"' % _fallback_is_tag


def test_stop():
    m = MagicMock()
    with patch('icap.server._server', m):
        stop()

        import icap.server
        assert icap.server._server is None

        # make sure multiple stop calls don't cause an error
        stop()

    m.close.assert_any_call()


def test_run_custom_factory():
    import icap.server
    assert icap.server._server is None

    factory = MagicMock()

    with patch('asyncio.get_event_loop') as get_event_loop:
        run(factory_class=factory, foo='bar')

        factory.assert_any_call(foo='bar')
        get_event_loop.assert_any_call()
        loop = get_event_loop.return_value
        loop.create_server.assert_any_call(factory.return_value, '127.0.0.1', 1334)
        server = loop.run_until_complete.return_value

        assert icap.server._server == server

        stop()


def test_run():

    import icap.server
    assert icap.server._server is None

    with patch('asyncio.get_event_loop') as get_event_loop, \
            patch('icap.asyncio.ICAPProtocolFactory') as factory_class:
        loop = get_event_loop.return_value

        run(foo='bar')
        factory_class.assert_any_call(foo='bar')
        get_event_loop.assert_any_call()

        loop.create_server.assert_any_call(factory_class.return_value, '127.0.0.1', 1334)

        server = loop.run_until_complete.return_value

        assert icap.server._server == server

        stop()
