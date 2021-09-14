#include <iostream>
#include <vector>
#include "remote_prov_utils.h"
#include <gtest/gtest.h>
#include "RpcHardwareInfo.h"

using namespace keymaster::javacard::test;

int main(int /*argc*/, char** /*argv*/) {
    //::testing::InitGoogleTest(&argc, argv);
    std::vector<uint8_t> eekId('a', 10);
    auto eekChain = generateEekChain(RpcHardwareInfo::CURVE_P256, 2, eekId);
    if (!eekChain) std::cout << "Failed to generate EEK Chain." << std::endl;
    else std::cout << "Generated EEK Chain Successfully." << std::endl;
    return 0;
}
