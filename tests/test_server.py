
import pytest

from icap import hooks
from icap.server import is_tag, _fallback_is_tag


class TestISTag:
    def test_is_tag__valid_values(self):
        hooks('is_tag')(lambda request: 'a string')
        assert is_tag(None) == '"a string"'

    @pytest.mark.parametrize(('expected_is_tag', 'endswith'), [
        ('1'*31+'2', '2'),
        ('1'*30+'23', '3'),
        ('lamp', 'lamp'),
    ])
    def test_is_tag__maximum_length(self, expected_is_tag, endswith):
        hooks('is_tag')(lambda request: expected_is_tag)
        tag = is_tag(None)
        assert tag.endswith(endswith+'"')
        assert len(tag) <= 34

    def test_is_tag__error(self):
        @hooks('is_tag')
        def is_tag_bad(request):
            raise Exception('boom')

        assert is_tag(None) == '"%s"' % _fallback_is_tag
