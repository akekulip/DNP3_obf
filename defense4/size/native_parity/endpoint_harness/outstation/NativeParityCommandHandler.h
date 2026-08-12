// SPDX-License-Identifier: Apache-2.0
//
// NativeParityCommandHandler — configured-endpoint command handler for the DNP3
// size-axis native-parity gate (even = real, odd = decoy).
//
// PREMISE (endpoint preconfiguration REQUIRED). The parity operation is one native
// multi-CROB CommandSet: one EVEN, wired, real control point plus one or more ODD,
// configured-but-inert decoy control points. Every referenced index is a REAL,
// CONFIGURED endpoint point with a real handler. The wired (even) point drives a
// physical output; the odd decoys are configured and SELECT/OPERATE with status
// SUCCESS but drive NO physical action. An index that was never configured is
// rejected with CommandStatus::NOT_SUPPORTED. This models a firmware/relay
// configuration; it is NOT compatible with a completely unmodified outstation, so
// the gate is explicitly a configured-decoy gate.
//
// SAFETY INVARIANT ENFORCED AT CONSTRUCTION:
//   * the wired (real) index MUST be even;
//   * every configured decoy index MUST be odd.
// A construction that violates the parity map is a programming error and aborts,
// so a mis-mapped point can never silently become "real".
//
// OpenDNP3's stock SimpleCommandHandler returns a single status for every index and
// never distinguishes configured from unconfigured, or wired from inert. This handler
// adds exactly that endpoint model plus per-point counters so the outstation-side
// assertions (real executes once, odd decoys inert, unconfigured fails safe, a failed
// decoy fails the whole parity op, no unrequested point actuates) are directly
// observable from real callbacks.
//
// SOFTWARE ONLY. `physicalActuations` / `inertActuations` / `failedActuations` are a
// SIMULATED physical/inert mapping in software. No physical relay is touched. "Real
// fires once" means the one wired handler ran once; it is NOT physical-relay evidence.

#ifndef NATIVE_PARITY_COMMAND_HANDLER_H
#define NATIVE_PARITY_COMMAND_HANDLER_H

#include <opendnp3/outstation/SimpleCommandHandler.h>

#include <cassert>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

class NativeParityCommandHandler final : public opendnp3::SimpleCommandHandler
{
public:
    struct PointStat
    {
        bool configured = false; // is this a real, configured endpoint point?
        bool wired = false;      // wired to a physical output? (only the even real point)
        uint32_t selects = 0;    // Select() calls the outstation delivered for this index
        uint32_t operates = 0;   // Operate() calls the outstation delivered for this index
    };

    // realIndex is the single wired control (MUST be even); decoyIndices are configured-but-inert
    // (each MUST be odd). The parity invariant is enforced here so it cannot be silently violated.
    NativeParityCommandHandler(uint16_t realIndex, const std::vector<uint16_t>& decoyIndices)
        : opendnp3::SimpleCommandHandler(opendnp3::CommandStatus::SUCCESS), realIdx(realIndex)
    {
        assert((realIndex % 2u) == 0u && "SAFETY: the real (wired) index MUST be even");
        PointStat realStat;
        realStat.configured = true;
        realStat.wired = true;
        stats[realIndex] = realStat;
        for (auto d : decoyIndices)
        {
            assert((d % 2u) == 1u && "SAFETY: every decoy index MUST be odd");
            PointStat s;
            s.configured = true;
            s.wired = false;
            stats[d] = s;
        }
    }

    bool isConfigured(uint16_t index) const
    {
        auto it = stats.find(index);
        return (it != stats.end()) && it->second.configured;
    }

    uint32_t selects(uint16_t index) const
    {
        auto it = stats.find(index);
        return (it == stats.end()) ? 0u : it->second.selects;
    }

    uint32_t operates(uint16_t index) const
    {
        auto it = stats.find(index);
        return (it == stats.end()) ? 0u : it->second.operates;
    }

    // Physical actuations = OPERATEs delivered to the one WIRED (even, real) control.
    uint32_t physicalActuations = 0;
    // Inert actuations = OPERATEs delivered to CONFIGURED odd decoys (SUCCESS, no output).
    uint32_t inertActuations = 0;
    // OPERATEs delivered to a configured decoy FORCED to a non-SUCCESS status.
    uint32_t failedActuations = 0;
    // Safe rejections of indices that were never configured.
    uint32_t unconfiguredSelectRejects = 0;
    uint32_t unconfiguredOperateRejects = 0;

    // Ordered log of every accepted OPERATE: (index, "PHYSICAL" | "INERT" | "FAILED").
    std::vector<std::pair<uint16_t, std::string>> operateLog;

    // Per-index endpoint state (only configured indices are pre-seeded).
    std::map<uint16_t, PointStat> stats;

    // Configured points told to fail: index -> forced (non-SUCCESS) status. Models a real,
    // configured point whose local device logic reports an error (e.g. HARDWARE_ERROR). The
    // point is still CONFIGURED (not unknown) but does not succeed. Used for both the
    // decoy-failure and the real-failure endpoint tests.
    std::map<uint16_t, opendnp3::CommandStatus> forced;

    void ForceStatus(uint16_t index, opendnp3::CommandStatus status)
    {
        forced[index] = status;
    }

    opendnp3::CommandStatus Select(const opendnp3::ControlRelayOutputBlock& command, uint16_t index) override
    {
        (void)command;
        if (!isConfigured(index))
        {
            ++unconfiguredSelectRejects;
            return opendnp3::CommandStatus::NOT_SUPPORTED; // fail safe: unknown point
        }
        ++stats[index].selects;
        auto f = forced.find(index);
        return (f == forced.end()) ? opendnp3::CommandStatus::SUCCESS : f->second;
    }

    opendnp3::CommandStatus Operate(const opendnp3::ControlRelayOutputBlock& command,
                                    uint16_t index,
                                    opendnp3::IUpdateHandler& handler,
                                    opendnp3::OperateType opType) override
    {
        (void)command;
        (void)handler;
        (void)opType;
        if (!isConfigured(index))
        {
            ++unconfiguredOperateRejects;
            return opendnp3::CommandStatus::NOT_SUPPORTED; // fail safe: unknown point
        }
        auto& s = stats[index];
        ++s.operates;
        auto f = forced.find(index);
        if (f != forced.end())
        {
            ++failedActuations; // configured point reporting an error: no physical, no inert-success
            operateLog.emplace_back(index, "FAILED");
            return f->second;
        }
        if (s.wired)
        {
            ++physicalActuations;
            operateLog.emplace_back(index, "PHYSICAL");
        }
        else
        {
            ++inertActuations;
            operateLog.emplace_back(index, "INERT");
        }
        return opendnp3::CommandStatus::SUCCESS;
    }

private:
    uint16_t realIdx;
};

#endif // NATIVE_PARITY_COMMAND_HANDLER_H
