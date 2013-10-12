import functools
import re
import types
import urlparse

function_types = (
    types.FunctionType,
    types.MethodType,
    types.BuiltinFunctionType,
    types.BuiltinMethodType,
)


class Handler(object):
    """Handler decorator used for registering handler callables on services."""
    raw = False

    def __call__(self, *args, **kwargs):
        if len(args) > 1:
            raise ValueError('Only accepts single callable as positional arg')
        elif len(args):
            handler = args[0]
            if not callable(handler):
                raise ValueError('Wrapped object must be callable')
            self.set_callable(handler)
            return handler
        else:
            self.raw = kwargs.pop('raw', self.raw)
        return self

    def can_handle(self, message):
        """Return True if the wrapped function can handle a given request."""
        key = 'reqmod' if message.is_reqmod else 'respmod'
        return bool(self.call_dict[key])

    def handle(self, message):
        """Process a given message.

        Assumes that :func:`self.can_handle` has been called on *message*.
        """
        key = 'reqmod' if message.is_reqmod else 'respmod'
        callable = self.call_dict[key]

        if callable is None:
            return

        if not self.raw:
            message = message.http
        return callable(message)

    def set_callable(self, callable):
        """Set the inner handler callable, mapping its capabilities for
        handling REQMODs and RESPMODs.

        *callable* may be either a function or a class/instance.

        if *callable* is a class/instance:
            - methods called 'reqmod' and 'respmod' will be used for handling,
              if present.

        if *callable* is a function/method:
            - the supported capabilities will be inferred based on the name. If
              the name includes 'reqmod', then REQMOD support is assumed. Else,
              RESPMOD.
        """
        if isinstance(callable, (types.ClassType, types.TypeType)):
            callable = callable()

        if isinstance(callable, function_types):
            name = callable.__name__
            reqmod = None
            respmod = None
            if 'reqmod' in name:
                reqmod = callable
            if 'respmod' in name:
                respmod = callable
        else:
            reqmod = getattr(callable, 'reqmod', None)
            respmod = getattr(callable, 'respmod', None)

        self.call_dict = {
            'reqmod': reqmod,
            'respmod': respmod,
        }


class ServiceRegistry(object):
    """Registry class that stores references to instances of
    :class:`BaseService`, so they can be dispatched to.
    """
    services = []

    @classmethod
    def add(cls, instance):
        cls.services.append(instance)

    @classmethod
    def remove(cls, instance):
        cls.services.remove(instance)

    @classmethod
    def finalize(cls):
        cls.services = sorted(cls.services, reverse=True)
        return cls.services


@functools.total_ordering
class BaseService(object):
    """Base Service class. Handles ServiceRegistry registration, and provides a
    foundation for implementation of custom service handlers.
    """
    handler_cls = Handler
    priority = 1

    def __init__(self):
        ServiceRegistry.add(self)
        self._handlers = []

    def __lt__(self, other):
        return self.priority < other.priority

    def __del__(self):
        ServiceRegistry.remove(self)

    def can_handle(self, request):
        raise NotImplementedError()

    def handle(self, request):
        handler = self.get_handler(request)

        if handler:
            return handler.handle(request)
        else:
            raise ValueError()

    def get_handler(self, request):
        for handler in self._handlers:
            if handler.can_handle(request):
                return handler

    @property
    def handler(self):
        handler = self.handler_cls()
        self._handlers.append(handler)
        return handler


class RegexService(BaseService):
    """Service that processes requests based on the URL, by a regex."""
    priority = 3

    def __init__(self, regex):
        super(RegexService, self).__init__()
        self.regex = re.compile(regex)

    def can_handle(self, request):
        url = urlparse.urlunparse(request.session['url'])
        return bool(self.regex.match(url))


class DomainService(RegexService):
    """Service that processes requests based on the domain.

    Supports globbing, e.g. "*google.com" matches "www.google.com", and
    "go?gle.com" matches "goggle.com" and "google.com".
    """
    priority = 2

    def __init__(self, *domains):
        domains_as_regexes = (s.replace('*', '.*').replace('?', '.')
                              for s in domains)
        domain_re = '^(%s)$' % '|'.join(domains_as_regexes)
        super(DomainService, self).__init__(domain_re)

    def can_handle(self, request):
        return bool(self.regex.match(request.session['url'].netloc))
