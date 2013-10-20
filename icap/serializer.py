from collections import OrderedDict

from werkzeug import http_date

from .utils import dump_encapsulated_field


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
            n = hex(len(s))[2:]  # strip off leading 0x

            header = chunk.header.strip()
            if header and header != 'ieof':
                header = '%s; %s' % (n, header)
            else:
                header = n

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
