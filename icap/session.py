"""
Helpers and factory functions for session management of REQMOD and RESPMOD requests.

Sessions are particularly useful for bridging REQMOD and RESPMOD requests,
something that the ICAP protocol does not provide by default.

A good ICAP client, e.g. Squid, will give request/response pairs an
X-Session-ID header so that you can easily match them up. This relies on that
behaviour.

TODO: Generate an ID from uniquely identifying headers, e.g. cookies, request line.
TODO: Make the X-Session-ID configurable.

"""

import asyncio
import re
import uuid
import logging

from .server import hooks


log = logging.getLogger(__name__)


@hooks('session_manager')
class SessionStorage:
    """Default session storage and management.

    Used for creating and destroying session data, i.e. a dictionary of
    information to be shared between matching REQMOD and RESPMOD requests.

    The default storage is an in memory dictionary, keyed by either the
    X-Session-ID header or a randomly generated UUID.

    If you want to provide your own implementation of a session+session
    management, perhaps using something like Redis, you can override the
    default SessionStorage with the 'session_manager' hook. Simply use the
    decorator on a class with ``get`` and ``finalize`` methods as below.

    """
    sessions = {}

    @classmethod
    def get(cls, session_id, request):
        """Return a session keyed by ``session_id`` for a given ``request``."""
        try:
            return cls.sessions[session_id]
        except KeyError:
            pass

        return cls.sessions.setdefault(session_id, {'id': session_id})

    @classmethod
    def finalize(cls, session_id):
        """Destroy the session keyed by ``session_id``. Return True if it was
        destroyed, False otherwise.

        """
        try:
            cls.sessions.pop(session_id)
        except KeyError:
            return False
        else:
            return True


def make_session_id(request):
    if 'X-Session-ID' in request.headers:
        session_id = request.headers['X-Session-ID']
    else:
        log.warning("X-Session-ID header not available, using UUID")
        # FIXME: generate id from headers
        session_id = uuid.uuid4().hex
    return session_id


@asyncio.coroutine
def get_session(request):
    from .asyncio import maybe_coroutine

    session_id = make_session_id(request)
    get = hooks['session_manager']().get

    session = yield from maybe_coroutine(get, session_id, request)

    if 'url' not in session:
        url = request.http.request_line.uri
        session['url'] = url

    return session


@asyncio.coroutine
def finalize_session(session_id):
    from .asyncio import maybe_coroutine

    finalize = hooks['session_manager']().finalize
    yield from maybe_coroutine(finalize, session_id)


def should_finalize_session(request):
    from .criteria import _HANDLERS

    # OPTIONS requests don't have sessions.
    if request.is_options:
        return False

    if request.is_respmod:
        return True

    if 'X-Session-ID' not in request.headers:
        return True

    url = request.request_line.uri
    resource = url.path.lower()
    respmod_equivalent = re.sub('/reqmod(/?)$', '/respmod', resource)

    if respmod_equivalent in _HANDLERS:
        return False

    return True
