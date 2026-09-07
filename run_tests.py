"""
run_tests.py
Runs every test_* function in test_log_parser.py and test_analyzer.py,
printing PASS/FAIL for each. No pytest dependency required.
"""

import test_log_parser
import test_analyzer


def run_module_tests(module):
    passed, failed = 0, 0
    for name in dir(module):
        if name.startswith("test_"):
            try:
                getattr(module, name)()
                print(f"PASS  {module.__name__}.{name}")
                passed += 1
            except AssertionError as e:
                print(f"FAIL  {module.__name__}.{name}  -> {e}")
                failed += 1
    return passed, failed


def main():
    total_passed = 0
    total_failed = 0

    for module in (test_log_parser, test_analyzer):
        passed, failed = run_module_tests(module)
        total_passed += passed
        total_failed += failed

    print()
    print(f"{total_passed} passed, {total_failed} failed")


if __name__ == "__main__":
    main()