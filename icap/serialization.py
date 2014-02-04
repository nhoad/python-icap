"""
Class and functions related to reserialization of requests/responses.

These are all to be considered private. You should not need to use them
directly except for special circumstances.
"""

import gzip
import logging
import re

from collections import OrderedDict

from werkzeug import http_date, cached_property

from .utils import dump_encapsulated_field


log = logging.getLogger(__name__)

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
    """Remove all unknown headers from the ICAP response that aren't prefixed
    with X-.
    """
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
    def __init__(self, response, is_tag, is_options=False):
        from .models import ICAPResponse
        assert isinstance(response, ICAPResponse)
        self.response = response
        self.is_tag = is_tag
        self.is_options = is_options

    def serialize_to_stream(self, stream):
        """Serialize the ICAP response and contained HTTP message to *stream*."""
        self.set_required_headers()
        remove_invalid_headers(self.response.headers, is_options=self.is_options)

        http_preamble = self.set_encapsulated_header()

        if self.response.status_line.code != 200 or self.is_options:
            stream.write(bytes(self.response))
            stream.write(b'\r\n')
            http = self.response.http
            if http and http.body_bytes:
                log.warning("opt-body is not supported")
            return

        # FIXME: need to serialize opt-body requests too.

        stream.write(bytes(self.response))
        stream.write(b'\r\n')
        stream.write(http_preamble)

        self.write_body(stream)

    @cached_property
    def is_gzipped(self):
        return 'gzip' in self.response.http.headers.get('Content-Encoding', '')

    def write_body(self, stream):
        """Write out each chunk to the given stream."""
        self.response.http.pre_serialization()

        if not self.response.http.body_bytes:
            return

        body = self.response.http.body_bytes
        if self.is_gzipped:
            # FIXME: this should be done in a thread
            body = gzip.compress(body)

        size = len(body)
        header = ('%x' % size).encode('utf8')
        stream.write(header+b'\r\n')
        stream.write(body+b'\r\n')
        stream.write(b'0\r\n\r\n')

    def set_encapsulated_header(self):
        """Serialize the http message preamble, set the encapsulated header,
        and return the serialized preamble.

        """
        if self.response.status_line.code != 200 or self.is_options:
            encapsulated = OrderedDict([('null-body', 0)])
            http_preamble = ''
        else:
            http = self.response.http
            http_preamble = bytes(http) + b'\r\n'

            if http.is_request:
                encapsulated = OrderedDict([('req-hdr', 0)])
                body_key = 'req-body'
            else:
                encapsulated = OrderedDict([('res-hdr', 0)])
                body_key = 'res-body'

            if not http or not http.body_bytes:
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
