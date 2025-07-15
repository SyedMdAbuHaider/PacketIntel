import unittest
from scapy.all import IP, TCP, UDP, DNS
from analyzers.protocol_stats import ProtocolStats

class TestProtocolStats(unittest.TestCase):
    def setUp(self):
        self.analyzer = ProtocolStats()
        
    def test_protocol_counting(self):
        packets = [
            IP()/TCP(),
            IP()/UDP(),
            IP()/TCP(),
            IP()/DNS()
        ]
        results = self.analyzer.analyze(packets)
        self.assertEqual(results['TCP'], 2)
        self.assertEqual(results['UDP'], 1)
        self.assertEqual(results['DNS'], 1)

if __name__ == '__main__':
    unittest.main()