#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Minimal unit test framework for FTC.

#include <cmath>
#include <cstdint>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace test {

// ---------------------------------------------------------------------------
// Test registry
// ---------------------------------------------------------------------------

struct TestCase {
    std::string suite;
    std::string name;
    std::function<void()> func;
};

inline std::vector<TestCase>& test_registry() {
    static std::vector<TestCase> registry;
    return registry;
}

inline int& fail_count() {
    static int count = 0;
    return count;
}

inline int& pass_count() {
    static int count = 0;
    return count;
}

inline std::string& current_test() {
    static std::string name;
    return name;
}

struct TestRegistrar {
    TestRegistrar(const char* suite, const char* name, std::function<void()> fn) {
        test_registry().push_back({suite, name, std::move(fn)});
    }
};

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

inline void check_impl(bool cond, const char* expr, const char* file, int line) {
    if (!cond) {
        std::cerr << "  FAIL: " << file << ":" << line
                  << ": CHECK(" << expr << ")" << std::endl;
        ++fail_count();
    } else {
        ++pass_count();
    }
}

template <typename A, typename B>
void check_eq_impl(const A& a, const B& b,
                   const char* a_expr, const char* b_expr,
                   const char* file, int line) {
    if (!(a == b)) {
        std::cerr << "  FAIL: " << file << ":" << line
                  << ": CHECK_EQ(" << a_expr << ", " << b_expr << ")"
                  << std::endl;
        ++fail_count();
    } else {
        ++pass_count();
    }
}

template <typename A, typename B>
void check_ne_impl(const A& a, const B& b,
                   const char* a_expr, const char* b_expr,
                   const char* file, int line) {
    if (!(a != b)) {
        std::cerr << "  FAIL: " << file << ":" << line
                  << ": CHECK_NE(" << a_expr << ", " << b_expr << ")"
                  << std::endl;
        ++fail_count();
    } else {
        ++pass_count();
    }
}

inline void check_near_impl(double a, double b, double eps,
                             const char* a_expr, const char* b_expr,
                             const char* file, int line) {
    if (std::fabs(a - b) > eps) {
        std::cerr << "  FAIL: " << file << ":" << line
                  << ": CHECK_NEAR(" << a_expr << ", " << b_expr
                  << ") diff=" << std::fabs(a - b) << std::endl;
        ++fail_count();
    } else {
        ++pass_count();
    }
}

// ---------------------------------------------------------------------------
// Macros
// ---------------------------------------------------------------------------

#define TEST_CASE(suite, name)                                       \
    static void test_##suite##_##name();                             \
    static ::test::TestRegistrar reg_##suite##_##name(               \
        #suite, #name, test_##suite##_##name);                       \
    static void test_##suite##_##name()

#define CHECK(expr) ::test::check_impl((expr), #expr, __FILE__, __LINE__)
#define CHECK_EQ(a, b) ::test::check_eq_impl((a), (b), #a, #b, __FILE__, __LINE__)
#define CHECK_NE(a, b) ::test::check_ne_impl((a), (b), #a, #b, __FILE__, __LINE__)
#define CHECK_NEAR(a, b, eps) ::test::check_near_impl((a), (b), (eps), #a, #b, __FILE__, __LINE__)

// Check that expression does not throw
#define CHECK_NOTHROW(expr) do {                                      \
    try { (expr); ++::test::pass_count(); }                           \
    catch (...) {                                                     \
        std::cerr << "  FAIL: " << __FILE__ << ":" << __LINE__       \
                  << ": CHECK_NOTHROW(" #expr ") threw" << std::endl;\
        ++::test::fail_count();                                      \
    }                                                                \
} while (0)

// Check that a Result<T> is ok
#define CHECK_OK(result_expr) do {                                    \
    auto&& _r = (result_expr);                                       \
    if (!_r.ok()) {                                                  \
        std::cerr << "  FAIL: " << __FILE__ << ":" << __LINE__       \
                  << ": CHECK_OK(" #result_expr ") failed: "        \
                  << _r.error().message() << std::endl;              \
        ++::test::fail_count();                                      \
    } else {                                                         \
        ++::test::pass_count();                                      \
    }                                                                \
} while (0)

// Check that a Result<T> is an error
#define CHECK_ERR(result_expr) do {                                   \
    auto&& _r = (result_expr);                                       \
    if (_r.ok()) {                                                   \
        std::cerr << "  FAIL: " << __FILE__ << ":" << __LINE__       \
                  << ": CHECK_ERR(" #result_expr ") was ok"         \
                  << std::endl;                                      \
        ++::test::fail_count();                                      \
    } else {                                                         \
        ++::test::pass_count();                                      \
    }                                                                \
} while (0)

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

inline int run_all_tests() {
    fail_count() = 0;
    pass_count() = 0;

    std::string last_suite;
    int tests_run = 0;

    for (auto& tc : test_registry()) {
        if (tc.suite != last_suite) {
            std::cout << "\n=== " << tc.suite << " ===" << std::endl;
            last_suite = tc.suite;
        }

        current_test() = tc.suite + "::" + tc.name;
        std::cout << "  " << tc.name << "... " << std::flush;

        int fails_before = fail_count();
        try {
            tc.func();
        } catch (const std::exception& e) {
            std::cerr << "\n  EXCEPTION: " << e.what() << std::endl;
            ++fail_count();
        } catch (...) {
            std::cerr << "\n  UNKNOWN EXCEPTION" << std::endl;
            ++fail_count();
        }

        if (fail_count() == fails_before) {
            std::cout << "ok" << std::endl;
        } else {
            std::cout << "FAILED" << std::endl;
        }
        ++tests_run;
    }

    std::cout << "\n========================================" << std::endl;
    std::cout << "Tests run: " << tests_run << std::endl;
    std::cout << "Checks passed: " << pass_count() << std::endl;
    std::cout << "Checks failed: " << fail_count() << std::endl;
    std::cout << "========================================" << std::endl;

    return fail_count() > 0 ? 1 : 0;
}

} // namespace test
