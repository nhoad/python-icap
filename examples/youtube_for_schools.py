"""
Example ICAP server that implements YouTube for Schools (http://www.youtube.com/schools)
"""
from icap import run, handler, DomainCriteria

# You must enter your school's YouTube for Schools ID here for this to work.
EDUCATION_ID = ''


@handler(DomainCriteria('youtube.com'))
class YouTubeForSchools:
    def reqmod(self, request):
        request.headers['X-YouTube-Edu-Filter'] = EDUCATION_ID


if __name__ == '__main__':
    run()
