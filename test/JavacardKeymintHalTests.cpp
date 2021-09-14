/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "sharedsecret_test"
#include <android-base/logging.h>

#include <JavacardKeymasterProxy.h>
#include <gtest/gtest.h>
#include <vector>

namespace keymaster::javacard::test {
using ::std::shared_ptr;
using ::std::vector;

class JavacardKeymintHalTests : public ::testing::Test {
  public:
    static void SetUpTestCase() { keymint_ = std::make_shared<JavacardKeymasterProxy>(4); }
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}

  private:
    static shared_ptr<JavacardKeymasterProxy> keymint_;
};

shared_ptr<JavacardKeymasterProxy> JavacardKeymintHalTests::keymint_;

TEST_F(JavacardKeymintHalTests, GetParameters) {
    GTEST_SKIP() << "Skipping the test because no shared secret service is found.";
}

TEST_F(JavacardKeymintHalTests, ComputeSharedSecretCorruptSeed) {
    GTEST_SKIP() << "Skipping the test as no shared secret service is found.";
}

}  // namespace keymaster::javacard::test
