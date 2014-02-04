import time

from icap import ICAPRequestParser, HTTPMessageParser


def benchmark(count, maximum_time, *args, **kwargs):
    def inner(func):
        s = time.time()
        for _ in range(count):
            func(*args, **kwargs)

        e = time.time()
        total = e - s
        per_request = total / count

        print('took %.5f seconds (%.10f per call for %d calls)' % (total, per_request, count))
        assert per_request < maximum_time
        return func
    return inner


@benchmark(200, 0.15, request=open('data/request_with_http_response_and_payload.request', 'rb').read())
def benchmark_ICAP_parsing(request):
    ICAPRequestParser.from_bytes(request)


@benchmark(1000, 0.20, request=open('data/http_request_with_payload.request', 'rb').read())
def benchmark_HTTP_parsing(request):
    HTTPMessageParser.from_bytes(request)
