// Copyright (c) 2020, Brandon Lehmann
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <crypto.h>

#define PRINT(value) std::cout << #value << ": " << std::endl << value << std::endl << std::endl
#define FAILED                                            \
    std::cout << "TEST FAILED" << std::endl << std::endl; \
    return 1

// Test vectors from https://github.com/satoshilabs/slips/blob/master/slip-0010.md

static bool test(const crypto_hd_key_t &key, const std::string &public_key, const std::string &secret_key)
{
    const auto [pk, sk] = key.keys();

    if (sk != crypto_secret_key_t(secret_key))
    {
        return false;
    }

    if (pk != crypto_public_key_t(public_key))
    {
        return false;
    }

    return true;
}

int main()
{
    {
        const auto raw_seed = Serialization::from_hex("000102030405060708090a0b0c0d0e0f");

        const auto seed = crypto_seed_t(raw_seed);

        PRINT(seed);
        PRINT(seed.key());
        PRINT(seed.chain_code());

        {
            const auto key = seed.generate_child_key();
            PRINT(key);

            if (!test(
                    key,
                    "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
                    "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"))
            {
                FAILED;
            }
        }

        {
            const auto key = seed.generate_child_key(0);
            PRINT(key);

            if (!test(
                    key,
                    "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
                    "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"))
            {
                FAILED;
            }
        }

        {
            const auto key = seed.generate_child_key(0, 1);
            PRINT(key);

            if (!test(
                    key,
                    "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
                    "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"))
            {
                FAILED;
            }
        }

        {
            const auto key = seed.generate_child_key(0, 1, 2);
            PRINT(key);

            if (!test(
                    key,
                    "ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
                    "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9"))
            {
                FAILED;
            }
        }

        {
            const auto key = seed.generate_child_key(0, 1, 2, 2);
            PRINT(key);

            if (!test(
                    key,
                    "8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
                    "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662"))
            {
                FAILED;
            }
        }

        {
            const auto key = seed.generate_child_key(0, 1, 2, 2, 1000000000);
            PRINT(key);

            if (!test(
                    key,
                    "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
                    "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"))
            {
                FAILED;
            }
        }
    }

    {
        const auto raw_seed =
            Serialization::from_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a87"
                                    "84817e7b7875726f6c696663605d5a5754514e4b484542");

        const auto seed = crypto_seed_t(raw_seed);

        PRINT(seed);
        PRINT(seed.key());
        PRINT(seed.chain_code());

        {
            const auto key = seed.generate_child_key();
            PRINT(key);

            if (!test(
                    key,
                    "8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a",
                    "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012"))
            {
                FAILED;
            }
        }

        {
            const auto key = seed.generate_child_key(0);
            PRINT(key);

            if (!test(
                    key,
                    "86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037",
                    "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635"))
            {
                FAILED;
            }
        }

        {
            const auto key = seed.generate_child_key(0, 2147483647);
            PRINT(key);

            if (!test(
                    key,
                    "5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d",
                    "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4"))
            {
                FAILED;
            }
        }

        {
            const auto key = seed.generate_child_key(0, 2147483647, 1);
            PRINT(key);

            if (!test(
                    key,
                    "2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45",
                    "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c"))
            {
                FAILED;
            }
        }

        {
            const auto key = seed.generate_child_key(0, 2147483647, 1, 2147483646);
            PRINT(key);

            if (!test(
                    key,
                    "e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b",
                    "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72"))
            {
                FAILED;
            }
        }

        {
            const auto key = seed.generate_child_key(0, 2147483647, 1, 2147483646, 2);
            PRINT(key);

            if (!test(
                    key,
                    "47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0",
                    "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d"))
            {
                FAILED;
            }
        }
    }

    return 0;
}
