from unittest.mock import patch

from django.test import SimpleTestCase

from .utils import get_ip_city_by_geoip


class GeoIPUtilsTestCase(SimpleTestCase):
    def test_private_ip_does_not_require_geoip_database(self):
        with patch('common.utils.ip.geoip.utils.init_ip_reader', side_effect=AssertionError):
            self.assertEqual(str(get_ip_city_by_geoip('127.0.0.1')), 'LAN')
