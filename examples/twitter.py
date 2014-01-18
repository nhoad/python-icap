from lxml import html

from icap import run, handler, DomainHandler, ContentTypeHandler


@handler(DomainHandler('youtube.com') & ContentTypeHandler('text/html'))
class Twitter:
    def respmod(request):
        doc = html.document_fromstring(request.body.decode('utf8'))

        for promoted_tweet in doc.cssselect('.promoted-tweet'):
            promoted_tweet.drop_tree()

        return html.tostring(doc).encode('utf8')


if __name__ == '__main__':
    run()
