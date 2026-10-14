import base64, json, os, sys, unittest
sys.path.insert(0, os.path.dirname(__file__))
from sealform_check import is_sealed, is_sealed_file

V = json.load(open(os.path.join(os.path.dirname(__file__), "..", "..", "test-vectors", "validator.json"), encoding="utf-8"))

class Vectors(unittest.TestCase):
    def test_text(self):
        for c in V["text"]:
            self.assertEqual(is_sealed(c["value"]), c["sealed"], c["note"])
        self.assertFalse(is_sealed(None))
    def test_files(self):
        for i, c in enumerate(V["files"]):
            self.assertEqual(is_sealed_file(base64.b64decode(c["base64"])), c["sealed"], c["note"])

if __name__ == "__main__":
    unittest.main()
