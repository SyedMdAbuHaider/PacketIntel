import unittest
from scapy.all import IP, TCP
from analyzers.flag_analyzer import FlagAnalyzer

class TestFlagAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = FlagAnalyzer()
        
    def test_syn_scan_detection(self):
        # Create a SYN packet
        syn_packet = IP(src="192.168.1.1", dst="192.168.1.2")/TCP(flags="S")
        results = self.analyzer.analyze([syn_packet])
        self.assertEqual(results['syn_scans']["192.168.1.1"], 1)
        
    def test_normal_traffic(self):
        # Create a normal ACK packet
        ack_packet = IP(src="192.168.1.1", dst="192.168.1.2")/TCP(flags="A")
        results = self.analyzer.analyze([ack_packet])
        self.assertEqual(results['syn_scans'], {})

if __name__ == '__main__':
    unittest.main()