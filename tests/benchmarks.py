import time

from icap import ICAPRequestParser, HTTPMessageParser


def benchmark(count, maximum_time, *args, **kwargs):
    def inner(func):
        request = kwargs.get('request')

        s = time.time()
        for _ in range(count):
            func(*args, **kwargs)

        e = time.time()
        total = e - s
        per_request = total / count

        print('took {:.5f} seconds to process {:,d} bytes ({:.10f} seconds per call for {} calls)'.format(total, len(request)*count, per_request, count))
        assert per_request < maximum_time
        return func
    return inner


@benchmark(2200, 0.0005, request=open('data/request_with_http_response_and_payload.request', 'rb').read())
def benchmark_ICAP_parsing(request):
    ICAPRequestParser.from_bytes(request)


@benchmark(6000, 0.0002, request=open('data/http_request_with_payload.request', 'rb').read())
def benchmark_HTTP_parsing(request):
    HTTPMessageParser.from_bytes(request)


@benchmark(1800, 0.0007, request=open('data/ninemsn.com.au', 'rb').read())
def benchmark_HTTP_parsing(request):
    HTTPMessageParser.from_bytes(request)
