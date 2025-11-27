# PT Journal Testing Guide

## Overview

PT Journal uses a comprehensive testing strategy with separate unit and integration test suites. All tests can be run with a single command for CI/CD integration.

## Test Organization

```text
tests/
├── unit/                    # Unit tests for individual components
│   ├── mod.rs              # Aggregates all unit tests
│   ├── chat_provider_tests.rs
│   ├── chatbot_unit_tests.rs
│   ├── controller_tests.rs
│   ├── domain_model_tests.rs
│   ├── session_content_tests.rs
│   ├── store_tests.rs
│   ├── tool_execution_unit_tests.rs
│   └── ui_tests.rs
└── integration/            # Integration tests for component interactions
    ├── integration_tests.rs
    └── test_runner.rs
```

## Running Tests

### Unified Test Suite

Run all tests, linting, and formatting checks:

```bash
./test-all.sh
```

### Individual Test Suites

**Unit Tests** (95 tests):

```bash
cargo test --test unit_tests
```

**Integration Tests** (11 tests):

```bash
cargo test --test integration_tests
```

**All Tests** (including doctests):

```bash
cargo test
```

### Development Workflow

**Quick Test** (just unit tests):

```bash
cargo test --test unit_tests
```

**Full Validation** (tests + quality checks):

```bash
./test-all.sh
```

**Specific Test File**:

```bash
cargo test --test unit_tests -- chat_provider_tests
```

## Test Categories

### Unit Tests

- **Component Isolation**: Each test focuses on a single component
- **Fast Execution**: <1 second for all unit tests
- **Mock Dependencies**: External dependencies are mocked
- **Coverage**: 90%+ code coverage target

### Integration Tests

- **Component Interaction**: Tests how components work together
- **Real Dependencies**: Uses actual implementations
- **End-to-End Scenarios**: Tests complete workflows
- **Performance**: Validates real-world performance

## Test Profiles

The project uses optimized test profiles for better performance:

```toml
[profile.test]
opt-level = 1
debug = true
overflow-checks = true
```

## CI/CD Integration

The unified test script (`test-all.sh`) is designed for CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Run Tests
  run: ./test-all.sh
```

## Adding New Tests

 Unit Tests

1. Create test file in `tests/unit/`
2. Add module declaration to `tests/unit/mod.rs`
3. Follow naming convention: `{component}_tests.rs`

Integration Tests

1. Add tests to `tests/integration/integration_tests.rs`
2. Use the `test_runner` utility for test orchestration

## Test Utilities

### Test Runner

Located in `tests/integration/test_runner.rs`, provides:

- Test execution timing
- Result aggregation
- Failure reporting

### Common Test Dependencies

- `tempfile`: Temporary file creation
- `assert_matches`: Pattern matching assertions
- `httpmock`: HTTP API mocking
- `test-log`: Test logging

## Performance Benchmarks

Current test execution times:

- Unit tests: ~0.8 seconds
- Integration tests: ~0.2 seconds
- Clippy: ~1.4 seconds
- Format check: ~0.1 seconds
- **Total**: ~2.5 seconds

## Coverage Goals

- **Unit Tests**: 90%+ coverage
- **Integration Tests**: Key workflows covered
- **Regression Tests**: All reported bugs have tests

## Debugging Failed Tests

1. **Run specific test**:

   ```bash
   cargo test --test unit_tests -- --nocapture test_name
   ```

2. **Enable logging**:

   ```bash
   RUST_LOG=debug cargo test --test unit_tests
   ```

3. **Debug GTK tests** (if needed):

   ```bash
   GTK_DEBUG=interactive cargo test --test unit_tests
   ```

## Test Maintenance

- **Weekly**: Run full test suite
- **Before PR**: All tests must pass
- **After Refactoring**: Update affected tests
- **Performance Regression**: Monitor execution times
