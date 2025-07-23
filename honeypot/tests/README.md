# Tests Directory

This directory is intended for unit and integration tests for the honeypot-ml pipeline.

## How to Add Tests
- Add Python test files (e.g., `test_feature.py`, `test_model.py`) using `unittest` or `pytest`.
- Test feature extraction, model predictions, and response logic.
- Example:
  ```python
  import unittest
  from honeypot-ml.ml.Feature import FeatureExtractor

  class TestFeatureExtractor(unittest.TestCase):
      def test_transform(self):
          fe = FeatureExtractor()
          log = {"timestamp": "2024-01-01T12:00:00", "auth_attempts": {"failed": 1, "success": 0}, "commands": []}
          features = fe.transform(log)
          self.assertIn("hour_of_day", features)

  if __name__ == "__main__":
      unittest.main()
  ```
