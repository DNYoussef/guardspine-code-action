"""Stdlib-only preflight controls; runs on the CI host before image building."""
import hashlib
import unittest

from check_blob_pins import verify


class BlobPinControls(unittest.TestCase):
    def test_valid_and_invalid_maps(self):
        content = b'canonical\nbytes\n'
        blobs = {str(i): content for i in range(27)}
        expected = {path: hashlib.sha256(data).hexdigest() for path, data in blobs.items()}
        verify(expected, blobs.__getitem__)
        bad = dict(expected, **{'0': '0' * 64})
        with self.assertRaisesRegex(ValueError, 'Git blob pin mismatch: 0'):
            verify(bad, blobs.__getitem__)
        with self.assertRaisesRegex(ValueError, 'Git blob pin mismatch: 0'):
            verify(expected, lambda path: blobs[path].replace(b'\n', b'\r\n'))
        with self.assertRaisesRegex(ValueError, 'Invalid pin entry'):
            verify(dict(expected, **{'0': 'a' * 63}), blobs.__getitem__)
        with self.assertRaisesRegex(ValueError, 'exactly 27'):
            verify({}, blobs.__getitem__)
        with self.assertRaisesRegex(ValueError, 'exactly 27'):
            verify(dict(expected, extra='a' * 64), blobs.__getitem__)
        missing = dict(expected)
        missing['missing'] = missing.pop('16')
        # The dict reader's KeyError stands in for Git's CalledProcessError;
        # neither missing-file failure is swallowed by the comparator.
        with self.assertRaises(KeyError):
            verify(missing, blobs.__getitem__)


if __name__ == '__main__':
    result = unittest.main(exit=False).result
    if not result.wasSuccessful() or result.testsRun != 1 or result.skipped:
        raise SystemExit(1)
    print('BLOB_PIN_CONTROLS_VERIFIED')
