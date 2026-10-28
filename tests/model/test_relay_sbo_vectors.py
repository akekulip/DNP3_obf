import importlib.util
from pathlib import Path
import unittest

HERE = (Path(__file__).resolve().parents[2] / 'scripts/model')
spec = importlib.util.spec_from_file_location('relay_sbo_vectors', HERE / 'relay_sbo_vectors.py')
vectors = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vectors)


class RelayVectors(unittest.TestCase):
    def test_all_transport_sequences_and_both_failure_statuses(self):
        for seq in range(64):
            for statuses in ((0, 0), (3, 0), (0, 1), (4, 5)):
                request = vectors.control_frame(seq, seq % 16)
                native = vectors.control_frame(seq, seq % 16, response=True, statuses=statuses)
                image = vectors.control_image(native)
                self.assertEqual((len(request), len(native), len(image)), (45, 49, 60))
                users, sizes, raw = [], [], image
                while raw:
                    nuser = raw[2] - 5
                    n = 10 + nuser + 2 * ((nuser + 15) // 16)
                    sizes.append(n)
                    users.append(vectors.std.deframe(raw[:n])[1])
                    raw = raw[n:]
                self.assertEqual(sizes, [28, 32])
                self.assertEqual(b''.join(u[1:] for u in users), vectors.std.deframe(native)[1][1:])

    def test_read49_shape_is_never_encoded_as_control(self):
        raw = bytes.fromhex('05642644010000002f77c7c08180000a02000016010101010101f3c601010101010101010101010101010101bbc301a1c9')
        with self.assertRaises(ValueError):
            vectors.control_image(raw)


if __name__ == '__main__':
    unittest.main()
