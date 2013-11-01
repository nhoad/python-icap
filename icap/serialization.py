"""
Class and functions related to reserialization of requests/responses.

These are all to be considered private. You should not need to use them
directly except for special circumstances.
"""

import re

from collections import OrderedDict, namedtuple

from werkzeug import http_date

from .utils import dump_encapsulated_field


# who could resist a class name like this?
BodyPart = namedtuple('BodyPart', 'content header')

response_headers = re.compile('(%s)' % '|'.join([
    'cache-control',
    'connection',
    'date',
    'encapsulated',
    'expires',
    'istag',
    'pragma',
    'server',
    'trailer',
    'upgrade',
]))

options_response_headers = re.compile('(%s)' % '|'.join([
    'allow',
    'max-connections',
    'methods',
    'opt-body-type',
    'options-ttl',
    'preview',
    'service',
    'service-id',
    'transfer-complete',
    'transfer-ignore',
    'transfer-preview',
]))


def remove_invalid_headers(headers, is_options=False):
    invalid = set()
    opt_match = options_response_headers.match
    match = response_headers.match

    for header in headers:
        if header.startswith('x-'):
            continue
        elif is_options and opt_match(header):
            continue
        elif match(header):
            continue
        invalid.add(header)

    for header in invalid:
        del headers[header]


class Serializer(object):
    """A class for serializing ICAP responses to a stream.

    This class should never be used directly. It is for internal usage only.

    """
    def __init__(self, response, is_tag, is_options=False, should_close=False):
        from .models import ICAPResponse
        assert isinstance(response, ICAPResponse)
        self.response = response
        self.is_tag = is_tag
        self.is_options = is_options
        self.should_close = should_close

    def serialize_to_stream(self, stream):
        """Serialize the ICAP response and contained HTTP message to *stream*."""
        self.set_required_headers()
        remove_invalid_headers(self.response.headers, is_options=self.is_options)

        http_preamble = self.set_encapsulated_header()

        if self.response.status_line.code != 200 or self.is_options:
            stream.write(str(self.response))
            stream.write('\r\n')
            stream.flush()
            return

        # FIXME: need to serialize opt-body requests too.

        stream.write(str(self.response))
        stream.write('\r\n')
        stream.write(http_preamble)

        self.write_body(stream)

    def write_body(self, stream):
        """Write out each chunk to the given stream."""
        if not self.response.http.body:
            stream.flush()
            return

        for chunk in self.response.http.body:
            s = chunk.content
            n = len(s)

            header = chunk.header.strip()
            if header and header != 'ieof':
                header = '%x; %s' % (n, header)
            else:
                header = '%x' % n

            stream.write(header+'\r\n')
            stream.write(s+'\r\n')

        stream.write('0\r\n\r\n')
        stream.flush()

    def set_encapsulated_header(self):
        """Serialize the http message preamble, set the encapsulated header,
        and return the serialized preamble.
        """
        if self.response.status_line.code != 200 or self.is_options:
            encapsulated = OrderedDict([('null-body', 0)])
            http_preamble = ''
        else:
            http = self.response.http
            http_preamble = str(http) + '\r\n'

            if http.is_request:
                encapsulated = OrderedDict([('req-hdr', 0)])
                body_key = 'req-body'
            else:
                encapsulated = OrderedDict([('res-hdr', 0)])
                body_key = 'res-body'

            if not http or not http.body:
                body_key = 'null-body'

            encapsulated[body_key] = len(http_preamble)

        self.response.headers['Encapsulated'] = dump_encapsulated_field(encapsulated)

        return http_preamble

    def set_required_headers(self):
        """Sets headers required for the ICAP response.

        Currently these set ISTag and Date headers.
        """
        self.response.headers['Date'] = http_date()
        self.response.headers['ISTag'] = self.is_tag

        # TODO: remove all hop-by-hop headers
        # TODO: ensure required authorization headers are preserved


def bodypipe(source):
    """Factory function that returns an instance of :class:`MemoryBodyPipe` or
    :class:`StreamBodyPipe`, depending on the input.
    """
    if hasattr(source, 'readline') and hasattr(source, 'read'):
        return StreamBodyPipe(source)
    return MemoryBodyPipe(source or [])


class MemoryBodyPipe(list):
    """An iterator over in-memory objects, e.g. a list, a string,
    or a generator.
    """
    def __init__(self, value):
        self.consumed = True

        if isinstance(value, str):
            value = [BodyPart(value, '')]
        elif isinstance(value, BodyPart):
            value = [value]

        try:
            iter(value)
        except TypeError:
            raise
        else:
            chunks = []
            for v in value:
                if not isinstance(v, BodyPart):
                    v = BodyPart(v, '')
                chunks.append(v)
            chunks = chunks

        super(MemoryBodyPipe, self).__init__(chunks)


class StreamBodyPipe(object):
    """An iterator over a stream, e.g. StringIO or a file.

    This is the on `body` attribute on instances of
    :class:`icap.models.HTTPRequest` and :class:`icap.models.HTTPResponse`.
    Iterating over this object will yield an instance of `BodyPart`, containing
    a part of the payload.

    This is akin to the chunked Transfer-Encoding header in HTTP. For
    non-chunked messages, aa single `BodyPart` will be yielded containing the
    payload.
    """
    def __init__(self, source):
        self.chunks = []
        self.consumed = False
        self.stream = source

    def __iter__(self):
        chunks = self.chunks

        if self.consumed:
            for chunk in chunks:
                yield chunk
            return

        while True:
            line = self.stream.readline().strip()

            # FIXME: this should handle short reads.
            try:
                size, header = line.split(';', 1)
            except ValueError:
                size = line
                header = ''

            # needs support for trailers
            size = int(size, 16)
            if size:
                # FIXME: non-crlf-endings
                data = self.stream.read(size+2)  # +2 for CRLF
                # FIXME: non-crlf-endings
                chunk = BodyPart(data[:-2], header)
                chunks.append(chunk)
                yield chunk
            else:
                # end of stream, get rid of trailing newline
                self.stream.readline()
                self.consumed = True
                return

    def consume(self):
        """Consume the input stream. Typically used for reserialization. Should
        not need to be used directly.
        """
        if not self.consumed:
            for chunk in self:
                pass
            self.consumed = True
        assert self.consumed

    def __bool__(self):
        self.consume()
        return bool(self.chunks)

    def __len__(self):
        self.consume()
        return len(self.chunks)

