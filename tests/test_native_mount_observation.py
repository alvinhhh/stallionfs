"""Borrowed descriptor behavior for native mount observations."""
import fcntl
import os
import tempfile
import unittest

from stallionfs._scan import mount_for_descriptor


def descriptor_state(descriptor):
    info = os.fstat(descriptor)
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            os.lseek(descriptor, 0, os.SEEK_CUR),
            fcntl.fcntl(descriptor, fcntl.F_GETFL),
            fcntl.fcntl(descriptor, fcntl.F_GETFD))


class MountObservation(unittest.TestCase):
    def test_regular_file_and_file_object_preserve_borrowed_descriptor(self):
        with tempfile.TemporaryFile(buffering=0) as stream:
            stream.write(b'owned file contents')
            stream.seek(3)
            descriptor = stream.fileno()
            before = descriptor_state(descriptor)
            from_integer = mount_for_descriptor(descriptor)
            self.assertEqual(descriptor_state(descriptor), before)
            from_file = mount_for_descriptor(stream)
            self.assertEqual(descriptor_state(descriptor), before)
            self.assertEqual(from_file, from_integer)
            self.assertEqual(stream.read(), b'ed file contents')

    def test_conversion_errors_leave_live_caller_descriptor_usable(self):
        with tempfile.TemporaryFile(buffering=0) as stream:
            stream.write(b'caller retains ownership')
            stream.seek(7)
            descriptor = stream.fileno()
            before = descriptor_state(descriptor)
            for argument, error in ((None, TypeError), (-1, ValueError),
                                    (1 << 100, OverflowError)):
                with self.subTest(argument=argument):
                    with self.assertRaises(error):
                        mount_for_descriptor(argument)
                    self.assertEqual(descriptor_state(descriptor), before)
            self.assertEqual(stream.read(), b'retains ownership')


if __name__ == '__main__':
    unittest.main()
