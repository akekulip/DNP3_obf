// SPDX-License-Identifier: Apache-2.0
//
// NativeParityPlan — the master-side index plan for a K-CROB native parity operation.
//
// A parity operation is K total CROBs in ONE CommandSet: one EVEN real control point
// plus (K-1) ODD configured decoy control points. The real point is index 0 (even);
// the decoys are the first (K-1) odd indices 1,3,5,... The indices are ascending, so
// the CommandSet request-order equals ascending-index order, which the outstation
// echoes back in the same order (opendnp3 matches SELECT/OPERATE records positionally).
//
// SIZE NOTE. The SBO wire size depends only on K and the qualifier width, NOT on the
// index values, as long as every index <= 255 (a one-byte index prefix is available).
// Non-contiguous even/odd indices therefore reproduce the SAME u_SBO(K) as contiguous
// indices while honouring the even=real / odd=decoy safety invariant.

#ifndef NATIVE_PARITY_PLAN_H
#define NATIVE_PARITY_PLAN_H

#include <cstdint>
#include <vector>

struct NativeParityPlan
{
    uint16_t realIndex;                 // even, wired
    std::vector<uint16_t> decoyIndices; // odd, configured-inert (size K-1)

    // All indices in CommandSet request order: real first, then odd decoys ascending.
    std::vector<uint16_t> ordered() const
    {
        std::vector<uint16_t> v;
        v.push_back(realIndex);
        for (auto d : decoyIndices)
            v.push_back(d);
        return v;
    }
};

// Plan for K total CROBs: real = index 0 (even); decoys = 1,3,5,... (K-1 odd indices).
inline NativeParityPlan parityPlan(uint16_t k)
{
    NativeParityPlan p;
    p.realIndex = 0; // even
    for (uint16_t j = 1; j < k; ++j)
        p.decoyIndices.push_back(static_cast<uint16_t>(2u * j - 1u)); // 1,3,5,...
    return p;
}

#endif // NATIVE_PARITY_PLAN_H
