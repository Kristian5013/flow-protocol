// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_framework.h"

#include <iostream>

int main(int argc, char* argv[]) {
    std::cout << "FTC Unit Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    return test::run_all_tests();
}
