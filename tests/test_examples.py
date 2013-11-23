from examples import withoutmypants, youtube_for_schools
from icap.parsing import HTTPMessageParser


def test_withoutmypants_modified():
    request = HTTPMessageParser.from_bytes(b"GET http://google.com/?q=foo HTTP/1.1\r\n\r\n")
    withoutmypants.reqmod(request)
    print(bytes(request))
    assert b"?q=foo+without+my+pants" in bytes(request)


def test_withoutmypants_not_modified():
    request = HTTPMessageParser.from_bytes(b"GET http://google.com/?qq=foo HTTP/1.1\r\n\r\n")
    withoutmypants.reqmod(request)
    print(bytes(request))
    assert b"without+my+pants" not in bytes(request)


def test_youtube_for_schools():
    request = HTTPMessageParser.from_bytes(b"GET http://youtube.com.com/?qq=foo HTTP/1.1\r\n\r\n")
    print(youtube_for_schools.YouTubeForSchools)
    youtube_for_schools.EDUCATION_ID = 'foo bar baz'
    youtube_for_schools.YouTubeForSchools().reqmod(request)
    print(bytes(request))
    assert b"X-YouTube-Edu-Filter: foo bar baz" in bytes(request)
