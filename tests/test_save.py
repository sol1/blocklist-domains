
import unittest
import cdblib
import blocklist_aggregator

from unittest.mock import patch


class TestSaving(unittest.TestCase):
    @patch('blocklist_aggregator.aggregator.requests.get')
    def test1_save_raw(self, mock_get):
        """test save list of domains as raw format"""
        fn = "./outputs/blocklist_raw.txt"
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "0.0.0.0 doubleclick.net"

        cfg_yaml = """
        verbose: false
        timeout: 5
        tlsverify: true
        whitelist: []
        blacklist: []
        sources:
          - pattern: '\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}\\b'
            urls: [ "https://mocked.com/list" ]
        """

        blocklist_aggregator.save_raw(filename=fn, cfg_update=cfg_yaml)
        
        with open(fn, "r") as f:
            data = f.read()
            
        domains = data.splitlines()  
        self.assertIn("doubleclick.net", domains)

    @patch('blocklist_aggregator.aggregator.requests.get')
    def test2_save_hosts(self, mock_get):
        """test save list of domains as hosts format"""
        fn = "./outputs/hosts.txt"
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "0.0.0.0 doubleclick.net"

        cfg_yaml = """
        verbose: false
        timeout: 5
        tlsverify: true
        whitelist: []
        blacklist: []
        sources:
          - pattern: '\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}\\b'
            urls: [ "https://mocked.com/list" ]
        """

        blocklist_aggregator.save_hosts(filename=fn, ip="0.0.0.0", cfg_update=cfg_yaml)
        
        with open(fn, "r") as f:
            data = f.read()
            
        domains = data.splitlines()  
        self.assertIn("0.0.0.0 doubleclick.net", domains)

    @patch('blocklist_aggregator.aggregator.requests.get')
    def test3_save_cdb(self, mock_get):
        """test save cdb"""
        fn = "./outputs/blocklist.cdb"
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "0.0.0.0 doubleclick.net"

        cfg_yaml = """
        verbose: false
        timeout: 5
        tlsverify: true
        whitelist: []
        blacklist: []
        sources:
          - pattern: '\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}\\b'
            urls: [ "https://mocked.com/list" ]
        """

        blocklist_aggregator.save_cdb(filename=fn, cfg_update=cfg_yaml)
        
        with open(fn, 'rb') as f:
            data = f.read()
        reader = cdblib.Reader(data)

        domains = []
        for key, _ in reader.iteritems():
            domains.append(key)
        self.assertIn(b"doubleclick.net", domains)