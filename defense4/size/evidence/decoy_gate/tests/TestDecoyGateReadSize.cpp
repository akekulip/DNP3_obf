// SPDX-License-Identifier: Apache-2.0
//
// PART B (READ counterpart) — configured real measurement points + inert decoy
// measurement points, read by the SAME all-points (class-0 integrity) poll from
// an UNMODIFIED master.
//
//   B1 value/flag invariance + master acceptance: a real opendnp3 outstation is
//      configured with R real analog points + K decoy analog points and produces
//      the class-0 response; those exact bytes are then delivered to a real
//      opendnp3 master that issued the standard IntegrityPoll(0). We assert the
//      master ACCEPTS the response and that every real point's VALUE and QUALITY
//      FLAG is byte-for-byte unchanged as K grows (they always equal the loaded
//      value, parsed out of a response that also carried K decoys).
//
//   B2 size / fragment / segment sweep: with K increasing we record the class-0
//      response SIZE (application bytes), the DNP3 application FRAGMENT count
//      (measured), and the transport-segment count (computed, 249 app bytes per
//      DNP3 transport segment). Under TCP_NODELAY one transport segment maps to
//      one link frame and one TCP segment; the on-wire TCP count is bounded by
//      [1, transport_segments] and otherwise depends on MSS and Nagle.
//
// Unlike SBO, the READ response is index-ordered and native-looking: decoys are
// just higher-index points, so the padded response needs no non-native encoding.

#include "utils/APDUHexBuilders.h"
#include "utils/MasterTestFixture.h"
#include "utils/MeasurementComparisons.h"
#include "utils/OutstationTestObject.h"

#include <dnp3mocks/DatabaseHelpers.h>

#include <opendnp3/app/MeasurementTypes.h>

#include <catch.hpp>

#include <cmath>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace opendnp3;

#define SUITE(name) "DecoyGateReadTestSuite - " name

namespace
{

constexpr uint16_t kReal = 4; // number of real (legit) analog points, indices 0..kReal-1

double realValue(uint16_t i)
{
    return 1000.0 + i;
}
double decoyValue(uint16_t idx)
{
    return 50000.0 + (idx - kReal);
}

size_t byteLen(const std::string& hex)
{
    std::istringstream ss(hex);
    std::string tok;
    size_t n = 0;
    while (ss >> tok)
        ++n;
    return n;
}

// Build+read a class-0 response from an outstation with kReal real + numDecoy decoy
// analog points. Returns the first application fragment hex (single-fragment regime).
std::string outstationClass0SingleFragment(uint16_t numDecoy)
{
    OutstationConfig config; // default maxTxFragSize (2048) -> single fragment for our sizes
    OutstationTestObject t(config, configure::by_count_of::analog_input(kReal + numDecoy));
    t.LowerLayerUp();
    t.Transaction([numDecoy](IUpdateHandler& db) {
        for (uint16_t i = 0; i < kReal; ++i)
            db.Update(Analog(realValue(i), Flags(0x01)), i);
        for (uint16_t j = 0; j < numDecoy; ++j)
            db.Update(Analog(decoyValue(kReal + j), Flags(0x01)), static_cast<uint16_t>(kReal + j));
    });
    t.SendToOutstation("C0 01 3C 01 06"); // read class 0 (all points)
    const std::string frag = t.lower->PopWriteAsHex();
    REQUIRE(t.lower->PopWriteAsHex().empty()); // exactly one application fragment
    return frag;
}

} // namespace

TEST_CASE(SUITE("B1: unmodified master accepts class-0 response; real values+flags unchanged as decoys grow"))
{
    const std::vector<uint16_t> ks = {0, 1, 2, 4, 8, 16};
    std::cout << "DECOY-READ[B1] real point invariance under decoy padding (R=" << kReal << " real):\n";

    for (auto k : ks)
    {
        const std::string resp = outstationClass0SingleFragment(k);

        // an unmodified master issues the SAME integrity poll and receives the padded response
        MasterParams params;
        params.disableUnsolOnStartup = false;
        params.unsolClassMask = ClassField::None();
        MasterTestFixture t(params);
        t.context->OnLowerLayerUp();
        t.exe->run_many();

        REQUIRE(t.lower->PopWriteAsHex() == hex::IntegrityPoll(0)); // same all-points READ every time
        t.context->OnTxReady();
        REQUIRE(t.SendToMaster(resp)); // master parses/accepts the decoy-augmented response

        // master accepted and delivered every point (real + decoy)
        REQUIRE(t.meas->TotalReceived() == static_cast<uint32_t>(kReal + k));

        // every REAL point's value AND quality flag is unchanged (equals the loaded value)
        for (uint16_t i = 0; i < kReal; ++i)
        {
            REQUIRE(t.meas->analogSOE.count(i) == 1);
            REQUIRE((t.meas->analogSOE[i].meas == Analog(realValue(i), Flags(0x01))));
        }

        std::cout << "  K=" << std::setw(2) << k << " decoys: response=" << std::setw(4) << byteLen(resp)
                  << " B, TotalReceived=" << (kReal + k) << ", real[0..3]=("
                  << t.meas->analogSOE[0].meas.value << "," << t.meas->analogSOE[1].meas.value << ","
                  << t.meas->analogSOE[2].meas.value << "," << t.meas->analogSOE[3].meas.value
                  << ") flags=0x" << std::hex << static_cast<int>(t.meas->analogSOE[0].meas.flags.value) << std::dec
                  << " -> UNCHANGED, master ACCEPTED\n";
    }
}

TEST_CASE(SUITE("B2: response size, DNP3 fragment count, transport-segment count vs decoy count"))
{
    // Table 1: default application fragment size (2048 B). Size and transport segments grow; app frags stay 1 until large K.
    std::cout << "DECOY-READ[B2] table1 maxTxFragSize=2048 (R=" << kReal
              << " real). cols: K | appBytes | dnp3AppFrags | transportSegs(=249B) | tcpSegs(NODELAY)\n";
    const std::vector<uint16_t> ks1 = {0, 1, 2, 4, 8, 16, 32, 64};
    for (auto k : ks1)
    {
        OutstationConfig config;
        OutstationTestObject t(config, configure::by_count_of::analog_input(kReal + k));
        t.LowerLayerUp();
        t.Transaction([k](IUpdateHandler& db) {
            for (uint16_t i = 0; i < kReal; ++i)
                db.Update(Analog(realValue(i), Flags(0x01)), i);
            for (uint16_t j = 0; j < k; ++j)
                db.Update(Analog(decoyValue(kReal + j), Flags(0x01)), static_cast<uint16_t>(kReal + j));
        });

        t.SendToOutstation("C0 01 3C 01 06");
        size_t bytes = 0, frags = 0, segs = 0;
        uint8_t seq = 0;
        while (true)
        {
            const std::string f = t.lower->PopWriteAsHex();
            if (f.empty())
                break;
            const size_t L = byteLen(f);
            ++frags;
            bytes += L;
            segs += static_cast<size_t>(std::ceil(L / 249.0));
            t.OnTxReady();
            char c[8];
            std::snprintf(c, sizeof(c), "C%X 00", seq & 0x0F); // confirm this fragment's sequence
            t.SendToOutstation(c);
            seq = static_cast<uint8_t>((seq + 1) & 0x0F);
        }
        std::printf("  K=%-3u | appBytes=%-5zu | dnp3AppFrags=%-2zu | transportSegs=%-2zu | tcpSegs<=%zu\n",
                    static_cast<unsigned>(k), bytes, frags, segs, segs);
    }

    // Table 2: small application fragment size to exhibit DNP3 application fragmentation growth.
    std::cout << "DECOY-READ[B2] table2 maxTxFragSize=64 (forces multi-fragment). cols same as table1\n";
    const std::vector<uint16_t> ks2 = {0, 4, 8, 16, 32};
    for (auto k : ks2)
    {
        OutstationConfig config;
        config.params.maxTxFragSize = 64;
        OutstationTestObject t(config, configure::by_count_of::analog_input(kReal + k));
        t.LowerLayerUp();
        t.Transaction([k](IUpdateHandler& db) {
            for (uint16_t i = 0; i < kReal; ++i)
                db.Update(Analog(realValue(i), Flags(0x01)), i);
            for (uint16_t j = 0; j < k; ++j)
                db.Update(Analog(decoyValue(kReal + j), Flags(0x01)), static_cast<uint16_t>(kReal + j));
        });

        t.SendToOutstation("C0 01 3C 01 06");
        size_t bytes = 0, frags = 0, segs = 0;
        uint8_t seq = 0;
        while (true)
        {
            const std::string f = t.lower->PopWriteAsHex();
            if (f.empty())
                break;
            const size_t L = byteLen(f);
            ++frags;
            bytes += L;
            segs += static_cast<size_t>(std::ceil(L / 249.0));
            t.OnTxReady();
            char c[8];
            std::snprintf(c, sizeof(c), "C%X 00", seq & 0x0F);
            t.SendToOutstation(c);
            seq = static_cast<uint8_t>((seq + 1) & 0x0F);
        }
        std::printf("  K=%-3u | appBytes=%-5zu | dnp3AppFrags=%-2zu | transportSegs=%-2zu | tcpSegs<=%zu\n",
                    static_cast<unsigned>(k), bytes, frags, segs, segs);
    }
}
