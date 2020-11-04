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

#ifndef CRYPTO_CONFIG_H
#define CRYPTO_CONFIG_H

#ifndef CRYPTO_BASE58_CHECKSUM_SIZE
#define CRYPTO_BASE58_CHECKSUM_SIZE 4
#endif

#ifndef CRYPTO_MINIMUM_SEED_TIMESTAMP
#define CRYPTO_MINIMUM_SEED_TIMESTAMP 1640995200
#endif

#ifndef CRYPTO_MAXIMUM_SEED_TIMESTAMP
#define CRYPTO_MAXIMUM_SEED_TIMESTAMP 10413792000
#endif

#ifndef CRYPTO_PBKDF2_ITERATIONS
#define CRYPTO_PBKDF2_ITERATIONS 10000
#endif

#ifndef CRYPTO_ENTROPY_BYTES
#define CRYPTO_ENTROPY_BYTES 32
#endif

#ifndef BENCHMARK_PERFORMANCE_ITERATIONS
#define BENCHMARK_PERFORMANCE_ITERATIONS 1000
#endif

#ifndef BENCHMARK_PERFORMANCE_ITERATIONS_LONG_MULTIPLIER
#define BENCHMARK_PERFORMANCE_ITERATIONS_LONG_MULTIPLIER 60
#endif

#ifndef BENCHMARK_PREFIX_WIDTH
#define BENCHMARK_PREFIX_WIDTH 70
#endif

#ifndef BENCHMARK_COLUMN_WIDTH
#define BENCHMARK_COLUMN_WIDTH 10
#endif

#ifndef BENCHMARK_PRECISION
#define BENCHMARK_PRECISION 3
#endif

#endif
