import os
import unittest
from security_sentinel.quarantine import Quarantine


class TestQuarantine(unittest.TestCase):
    def setUp(self):
        self.quarantine_dir = "test_quarantine_dir"
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.quarantine = Quarantine(self.quarantine_dir)

    def tearDown(self):
        for filename in os.listdir(self.quarantine_dir):
            file_path = os.path.join(self.quarantine_dir, os.path.basename(filename))
            os.remove(file_path)
        os.rmdir(self.quarantine_dir)

    def test_quarantine_file(self):
        test_file = "test_file.txt"
        with open(test_file, "w") as f:
            f.write("Sensitive data")

        self.quarantine.quarantine_file(test_file)

        self.assertFalse(os.path.exists(test_file))
        self.assertTrue(
            os.path.exists(
                os.path.join(self.quarantine_dir, os.path.basename(test_file))
            )
        )

    def test_quarantine_nonexistent_file(self):
        result = self.quarantine.quarantine_file("nonexistent_file.txt")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
