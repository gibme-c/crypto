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

#ifndef CRYPTO_SCALAR_TRANSCRIPT_T
#define CRYPTO_SCALAR_TRANSCRIPT_T

#include <crypto_common.h>
#include <serialization.h>

/**
 * Structure provides a transcript for hashing arbitrary values in a determinisic way
 * that can be used for constructing challenge scalars during commitments
 */
struct scalar_transcript_t
{
  public:
    scalar_transcript_t() = default;

    template<typename T> explicit scalar_transcript_t(const T &seed)
    {
        update(seed);
    }

    template<typename T, typename U> scalar_transcript_t(const T &seed, const U &seed2)
    {
        update(seed, seed2);
    }

    template<typename T, typename U, typename V> scalar_transcript_t(const T &seed, const U &seed2, const V &seed3)
    {
        update(seed, seed2, seed3);
    }

    template<typename T, typename U, typename V, typename W>
    scalar_transcript_t(const T &seed, const U &seed2, const V &seed3, const W &seed4)
    {
        update(seed, seed2, seed3, seed4);
    }

    template<typename T, typename U, typename V>
    scalar_transcript_t(const T &seed, const U &seed2, const std::vector<V> &seed3)
    {
        update(seed3, seed, seed2);
    }

    /**
     * Returns the challenge scalar given the current state of the transcript
     *
     * @return
     */
    crypto_scalar_t challenge()
    {
        return state;
    }

    /**
     * Returns the challenge scalar given the current state of the transcript as the given type
     *
     * @tparam T
     * @return
     */
    template<typename T> T challenge()
    {
        return T(state.serialize());
    }

    /**
     * Resets the transcript to its base state
     */
    void reset()
    {
        state = TRANSCRIPT_BASE;
    }

    /**
     * Updates the transcript with the value provided
     *
     * @tparam T
     * @param input
     */
    template<typename T> void update(const T &input)
    {
        Serialization::serializer_t writer;

        writer.pod(state);

        writer.pod(input);

        state = crypto_hash_t::sha3(writer.data(), writer.size()).scalar();
    }

    /**
     * Updates the transcript with the values provided
     *
     * @tparam T
     * @tparam U
     * @param input
     * @param input2
     */
    template<typename T, typename U> void update(const T &input, const U &input2)
    {
        Serialization::serializer_t writer;

        writer.pod(state);

        writer.pod(input);

        writer.pod(input2);

        state = crypto_hash_t::sha3(writer.data(), writer.size()).scalar();
    }

    /**
     * Updates the transcript with the values provided
     *
     * @tparam T
     * @tparam U
     * @tparam V
     * @param input
     * @param input2
     * @param input3
     */
    template<typename T, typename U, typename V> void update(const T &input, const U &input2, const V &input3)
    {
        Serialization::serializer_t writer;

        writer.pod(state);

        writer.pod(input);

        writer.pod(input2);

        writer.pod(input3);

        state = crypto_hash_t::sha3(writer.data(), writer.size()).scalar();
    }

    /**
     * Updates the transcript with the values provided
     *
     * @tparam T
     * @tparam U
     * @tparam V
     * @tparam W
     * @param input
     * @param input2
     * @param input3
     * @param input4
     */
    template<typename T, typename U, typename V, typename W>
    void update(const T &input, const U &input2, const V &input3, const W &input4)
    {
        Serialization::serializer_t writer;

        writer.pod(state);

        writer.pod(input);

        writer.pod(input2);

        writer.pod(input3);

        writer.pod(input4);

        state = crypto_hash_t::sha3(writer.data(), writer.size()).scalar();
    }

    /**
     * Updates the transcript with the vector of values provided
     *
     * @tparam T
     * @param input
     */
    template<typename T> void update(const std::vector<T> &input)
    {
        Serialization::serializer_t writer;

        writer.pod(state);

        writer.pod(input);

        state = crypto_hash_t::sha3(writer.data(), writer.size()).scalar();
    }

  private:
    // default seed state for scalar transcripts
    crypto_scalar_t state = TRANSCRIPT_BASE;
};

#endif // CRYPTO_SCALAR_TRANSCRIPT_T
