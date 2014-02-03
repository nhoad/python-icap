from lxml import html

from icap import run, handler, DomainCriteria, ContentTypeCriteria


@handler(DomainCriteria('youtube.com') & ContentTypeCriteria('text/html'))
class Twitter:
    def respmod(request):
        doc = html.document_fromstring(request.body)

        for promoted_tweet in doc.cssselect('.promoted-tweet'):
            promoted_tweet.drop_tree()

        return html.tostring(doc)


if __name__ == '__main__':
    run()
