import re
import functools

from asyncio.tasks import iscoroutine, Task
from collections import OrderedDict

from werkzeug import parse_dict_header

from .errors import InvalidEncapsulatedHeadersError


def convert_offsets_to_sizes(fields):
    """Convert the results from func:`parse_encapsulated_field` to sizes
    instead of offsets.

    The Encapsulated header describes an encapsulated's section start point
    relative to the start of the message body. This is confusing, so this
    method provides a cleaner way of reading that info.

    See RFC3507 4.4.1 for a further explanation.

    :param chunks: :class:`collections.OrderedDict` of encapsulated chunk
                   offsets.
    :return: :class:`collections.OrderedDict` of sizes.
    """
    encapsulated_by_sizes = OrderedDict()

    previous_offset = 0
    previous_name = None

    for name, offset in fields.items():
        size = offset - previous_offset
        if previous_name:
            encapsulated_by_sizes[previous_name] = size
        previous_name = name
        previous_offset = offset

    # this is ALWAYS going to be the last header, and thus the body.
    # we don't have a size for the body, so we read it in.
    # use a sentinel of -1 to indicate it's of unknown size.
    if previous_name == 'null-body':
        encapsulated_by_sizes[previous_name] = 0
    else:
        encapsulated_by_sizes[previous_name] = -1

    return encapsulated_by_sizes


b = lambda body: '(%s-body|null-body)' % body

#valid Encapsulated keys, according to RFC3507 section 4.4.1.
#REQMOD  request  encapsulated_list: [reqhdr] reqbody
#REQMOD  response encapsulatedlist: {[reqhdr] reqbody} | {[reshdr] resbody}
#RESPMOD request  encapsulated_list: [reqhdr] [reshdr] resbody
#RESPMOD response encapsulated_list: [reshdr] resbody
#OPTIONS response encapsulated_list: optbody

encapsulated_input_orders = {
    'REQMOD':  '^(req-hdr )?%s$' % b('req'),
    'RESPMOD': '^(req-hdr )?(res-hdr )?%s$' % b('res'),
}

encapsulated_output_orders = {
    'REQMOD': '(^(req-hdr )?%s$)|(^(res-hdr )?%s$)' % (b('req'), b('res')),
    'RESPMOD': '^(res-hdr )?%s$' % b('res'),
    'OPTIONS': '^%s$' % b('opt'),
}


del b


def compile_encapsulated(fields):
    for key, value in fields.items():
        fields[key] = re.compile(value)
    return fields


encapsulated_input_orders = compile_encapsulated(encapsulated_input_orders)
encapsulated_output_orders = compile_encapsulated(encapsulated_output_orders)


def parse_encapsulated_field(raw_field):
    """Parse an Encapsulated header, `raw_field`, and return it as an instance
    of `collections.OrderedDict`, according to RFC3507.

    Will raise :exc:`InvalidEncapsulatedHeadersError` if `raw_field` is not a
    valid ICAP Encapsulated request header, according to RFC3507 section 4.4.1.

    >>> from icap.utils import parse_encapsulated_field
    >>> parse_encapsulated_field('req-hdr=0, req-body=749')
    OrderedDict([('req-hdr', 0), ('req-body', 749)])

    :return: `collections.OrderedDict` containing the parsed encapsulated
             sections.
    """

    parsed = parse_dict_header(raw_field, cls=OrderedDict)

    keys = ' '.join(parsed)

    for regex in list(encapsulated_input_orders.values()):
        if regex.match(keys):
            return OrderedDict((key, int(value)) for (key, value)
                               in parsed.items())
    else:
        raise InvalidEncapsulatedHeadersError(raw_field)


def dump_encapsulated_field(field):
    """Serialize `field` to a string.

    Will raise :exc:`InvalidEncapsulatedHeadersError` if `field` is not a valid
    ICAP Encapsulated response header, according to RFC3507 section 4.4.1.

    >>> from icap.utils import dump_encapsulated_field
    >>> from collections import OrderedDict
    >>> d = OrderedDict([('res-hdr', 0), ('res-body', 50)])
    >>> dump_encapsulated_field(d)
    'res-hdr=0, res-body=50'

    :param field: an instance of :class:`collections.OrderedDict` to serialize.
    :return: a string representation of `field`
    """
    keys = ' '.join(field)

    for regex in list(encapsulated_output_orders.values()):
        if regex.match(keys):
            return ', '.join('%s=%d' % it for it in field.items())
    else:
        raise InvalidEncapsulatedHeadersError(field)


def maybe_coroutine(value):
    if iscoroutine(value):
        return value

    def coro():
        yield
        return value
    return coro()


def task(func):
    @functools.wraps(task)
    def caller(*args, **kwargs):
        f = func(*args, **kwargs)
        return Task(f)
    return caller
