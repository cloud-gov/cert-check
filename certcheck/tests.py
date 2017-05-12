from certcheck.sources import BoshDirector

import unittest

class TestBoshDirector(unittest.TestCase):

    def test_bosh(self):
    	b = BoshDirector('trololo')
    	self.assertEqual(b._boshcli[0],'trololo')

if __name__ == '__main__':
    unittest.main()