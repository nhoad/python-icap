import asyncio

from unittest.mock import patch, MagicMock

from icap import ICAPRequest, HeadersDict, handler
from icap.session import make_session_id, should_finalize_session, get_session, SessionStorage
from icap.criteria import _HANDLERS


def test_make_session_id():
    req = ICAPRequest()
    with patch('icap.session.uuid.uuid4') as mock_uuid:
        mock_uuid.return_value.hex = 'cool hash'
        assert make_session_id(req) == 'cool hash'

    req.headers['X-Session-ID'] = 'cool session id'

    assert make_session_id(req) == 'cool session id'


def test_SessionStorage():
    t = SessionStorage.get('foo', MagicMock())

    assert t['id'] == 'foo'
    assert 'foo' in SessionStorage.sessions
    assert SessionStorage.get('foo', MagicMock()) is t

    assert SessionStorage.finalize('foo')
    assert not SessionStorage.finalize('foo')

    assert 'foo' not in SessionStorage.sessions
    assert SessionStorage.get('foo', MagicMock()) is not t


def test_get_session():
    request = MagicMock(headers=HeadersDict())
    request.http.request_line.uri = 'foo'
    request.headers['X-Session-ID'] = 'bar'

    session = asyncio.get_event_loop().run_until_complete(get_session(request))

    assert session['url'] == 'foo'
    assert session['id'] == 'bar'


def test_should_finalize_session():
    _HANDLERS.clear()

    assert not should_finalize_session(MagicMock(is_options=True))
    assert should_finalize_session(MagicMock(is_options=False, is_respmod=True))
    assert should_finalize_session(MagicMock(is_options=False, is_respmod=False, headers=HeadersDict()))

    request = MagicMock(is_options=False, is_respmod=False, headers=HeadersDict())
    request.headers['X-Session-ID'] = 'foo'

    @handler()
    def respmod(request):
        pass

    @handler(name='foo')
    def respmod(request):
        pass

    for p in ['/reqmod', '/reqmod/', '/foo/reqmod', '/foo/reqmod/']:
        request.request_line.uri.path = p
        assert not should_finalize_session(request)

    for p in ['/bar/reqmod', '/bar/reqmod/']:
        request.request_line.uri.path = p
        assert should_finalize_session(request)
