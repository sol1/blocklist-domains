import unittest
import warnings
import blocklist_aggregator

from unittest.mock import patch


class TestFetching(unittest.TestCase):
    def setUp(self):
        warnings.filterwarnings('ignore', message='Unverified HTTPS request')

    @patch('blocklist_aggregator.aggregator.requests.get')
    def test1_fetch(self, mock_get):
        """test fetch"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "0.0.0.0 doubleclick.net"

        domains = blocklist_aggregator.fetch()
        
        self.assertIn("doubleclick.net", domains)
        self.assertNotIn("github.com", domains)

    @patch('blocklist_aggregator.aggregator.requests.get')
    def test2_blacklist(self, mock_get):
        """test blacklist feature"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = ""
        cfg_yaml = "blacklist: [ blocklist-helloworld.com ]"
        
        domains = blocklist_aggregator.fetch(cfg_update=cfg_yaml)
   
        self.assertIn("blocklist-helloworld.com", domains)

    @patch('blocklist_aggregator.aggregator.requests.get')
    def test3_whitelist(self, mock_get):
        """test whitelist feature"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "0.0.0.0 doubleclick.net"
        cfg_yaml = "whitelist: [ doubleclick.net ]"
        
        domains = blocklist_aggregator.fetch(cfg_update=cfg_yaml)
   
        self.assertNotIn("doubleclick.net", domains)

    @patch('blocklist_aggregator.aggregator.requests.get')
    def test4_load_external_config(self, mock_get):
        """test and load external config"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "0.0.0.0 helloworld-blacklist"
        domains = blocklist_aggregator.fetch(cfg_filename="./testsdata/blocklist.conf")
   
        self.assertIn("helloworld-blacklist", domains)
        self.assertNotIn("doubleclick.net", domains)