from unittest.mock import patch

from django.test import SimpleTestCase

from .utils import get_ip_city


class IPUtilsTestCase(SimpleTestCase):
    def test_missing_geoip_database_does_not_block_ip_lookup(self):
        with patch('common.utils.ip.utils.get_ip_city_by_geoip', side_effect=FileNotFoundError):
            self.assertEqual(str(get_ip_city('203.0.113.10')), 'Unknown')
