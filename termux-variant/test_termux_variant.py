"""Self-test for the Termux variant (stdlib unittest; run: python3 test_termux_variant.py)."""
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent)]

from revive_termux import patch, usbdevfs as u  # noqa: E402

DEV = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x200, 2, 0, 0, 64, 0x0E8D, 0x0003, 0x100, 0, 0, 0, 1)
CFG = bytes([9, 2, 39, 0, 2, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 2, 2, 1, 0, 9, 4, 1, 0, 2, 10, 0, 0, 0,
             7, 5, 0x81, 2, 0, 2, 0, 7, 5, 0x01, 2, 0, 2, 0])


class FakeDevice(u.TermuxUsbDevice):
    def __init__(self):
        for k, v in u.parse_descriptors(DEV + CFG).items():
            setattr(self, k, v)
        self._claimed, self.bus, self.address, self.path, self.fd = set(), 1, 5, "/dev/bus/usb/001/005", -1
        self.manufacturer = self.product = self.serial_number = ""
        self.calls = []

    def _ioctl(self, request, arg):
        self.calls.append(request)
        return 0


class TermuxVariantTest(unittest.TestCase):
    def test_ioctl_numbers_match_linux_headers(self):
        if struct.calcsize("P") != 8:
            self.skipTest("values below are for 64-bit")
        self.assertEqual(u.USBDEVFS_BULK, 0xC0185502)
        self.assertEqual(u.USBDEVFS_CONTROL, 0xC0185500)
        self.assertEqual(u.USBDEVFS_CLAIMINTERFACE, 0x8004550F)
        self.assertEqual(u.USBDEVFS_IOCTL, 0xC0105512)
        self.assertEqual(u.USBDEVFS_RESET, 0x5514)

    def test_descriptor_parsing(self):
        d = u.parse_descriptors(DEV + CFG)
        self.assertEqual((d["idVendor"], d["idProduct"]), (0x0E8D, 0x0003))
        eps = [e.bEndpointAddress for i in d["configs"][0] for e in i]
        self.assertEqual(eps, [0x81, 0x01])

    def test_patched_finder_and_open(self):
        patch.apply()
        from revive.backends import usbfinder
        from revive.core import usbmodes
        patch.DEVICES[:] = [FakeDevice()]
        try:
            devs, warn = usbfinder.find_devices(0x0E8D)
            self.assertEqual(len(devs), 1)
            eps = usbfinder.fast_open_device(devs[0])
            self.assertEqual((eps.out_ep, eps.in_ep, eps.interface), (0x01, 0x81, 1))
            self.assertIn(u.USBDEVFS_CLAIMINTERFACE, devs[0].calls)
            self.assertEqual(usbmodes.enumerate_devices()[0][0].mode, usbmodes.MODE_MTK_BROM)
        finally:
            patch.DEVICES[:] = []


if __name__ == "__main__":
    unittest.main()
