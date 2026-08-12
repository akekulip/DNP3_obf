// SPDX-License-Identifier: Apache-2.0
//
// DecoyGateCommandHandler — a configured-endpoint command handler for the DNP3
// size-axis "configured inert decoy" gate (Part A, outstation/endpoint side).
//
// PREMISE (endpoint preconfiguration REQUIRED). The decoy CROBs are REAL,
// CONFIGURED endpoint control points: valid indices with real handlers. They are
// simply NOT wired to a physical output, so they SELECT/OPERATE with status
// SUCCESS but drive no physical action. Exactly one configured index is "wired"
// (the legitimate control). An index that was never configured is rejected with
// CommandStatus::NOT_SUPPORTED. This models a firmware/relay configuration; it is
// NOT compatible with a completely unmodified outstation, which is why the gate is
// explicitly labelled a configured-decoy gate.
//
// OpenDNP3's stock SimpleCommandHandler returns a single status for every index
// and never distinguishes configured from unconfigured points. This handler adds
// exactly that endpoint model plus per-point counters so the outstation-side
// assertions (legit executes once, decoys are inert, unconfigured fails safe, no
// unrequested point actuates) are directly observable.

#ifndef DECOY_GATE_COMMAND_HANDLER_H
#define DECOY_GATE_COMMAND_HANDLER_H

#include <opendnp3/outstation/SimpleCommandHandler.h>

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

class DecoyGateCommandHandler final : public opendnp3::SimpleCommandHandler
{
public:
    struct PointStat
    {
        bool configured = false; // is this a real, configured endpoint point?
        bool wired = false;      // is it wired to a physical output? (only the legit point)
        uint32_t selects = 0;    // Select() calls the outstation delivered for this index
        uint32_t operates = 0;   // Operate() calls the outstation delivered for this index
    };

    // legitIndex is the single wired control; decoyIndices are configured-but-inert.
    DecoyGateCommandHandler(uint16_t legitIndex, const std::vector<uint16_t>& decoyIndices)
        : opendnp3::SimpleCommandHandler(opendnp3::CommandStatus::SUCCESS), legit(legitIndex)
    {
        PointStat legitStat;
        legitStat.configured = true;
        legitStat.wired = true;
        stats[legitIndex] = legitStat;
        for (auto d : decoyIndices)
        {
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

    // Physical actuations = OPERATEs delivered to the one WIRED (legit) control.
    uint32_t physicalActuations = 0;
    // Inert actuations = OPERATEs delivered to CONFIGURED decoys (SUCCESS, no output).
    uint32_t inertActuations = 0;
    // Safe rejections of indices that were never configured.
    uint32_t unconfiguredSelectRejects = 0;
    uint32_t unconfiguredOperateRejects = 0;

    // Ordered log of every accepted OPERATE: (index, "PHYSICAL" | "INERT").
    std::vector<std::pair<uint16_t, std::string>> operateLog;

    // Per-index endpoint state (only configured indices are pre-seeded).
    std::map<uint16_t, PointStat> stats;

    opendnp3::CommandStatus Select(const opendnp3::ControlRelayOutputBlock& command, uint16_t index) override
    {
        (void)command;
        if (!isConfigured(index))
        {
            ++unconfiguredSelectRejects;
            return opendnp3::CommandStatus::NOT_SUPPORTED; // fail safe: unknown point
        }
        ++stats[index].selects;
        return opendnp3::CommandStatus::SUCCESS;
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
    uint16_t legit;
};

#endif // DECOY_GATE_COMMAND_HANDLER_H
