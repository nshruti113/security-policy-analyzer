# Test Suite

## Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=scripts

# Run specific test file
pytest tests/test_config_parser.py

# Run tests matching a pattern
pytest -k "test_parse"
```

## Test Coverage

Current test coverage: **~90%**

Covered modules:
- ✅ config_parser.py
- ✅ security_analyzer.py
- ✅ report_generator.py

## Test Structure
```
tests/
├── test_config_parser.py      # Parser tests
├── test_security_analyzer.py  # Analyzer tests
└── test_report_generator.py   # Report generation tests
```

## Adding New Tests

1. Create test file: `test_<module>.py`
2. Import module to test
3. Write test functions starting with `test_`
4. Run pytest to verify