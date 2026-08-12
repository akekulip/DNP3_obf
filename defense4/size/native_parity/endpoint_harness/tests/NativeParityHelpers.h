// SPDX-License-Identifier: Apache-2.0
//
// NativeParityHelpers — byte/wire helpers shared by the native-parity endpoint tests.
// Everything derives from the ACTUAL serialized hex strings emitted by real opendnp3
// contexts; nothing hard-codes an expected length. Include AFTER <catch.hpp>.

#ifndef NATIVE_PARITY_HELPERS_H
#define NATIVE_PARITY_HELPERS_H

#include <catch.hpp>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

namespace np
{

// ----- hex-token helpers ----------------------------------------------------------------

inline std::vector<std::string> toks(const std::string& hex)
{
    std::istringstream ss(hex);
    std::vector<std::string> out;
    std::string t;
    while (ss >> t)
        out.push_back(t);
    return out;
}

inline size_t byteLen(const std::string& hex)
{
    return toks(hex).size();
}

inline int hb(const std::string& t)
{
    return std::stoi(t, nullptr, 16);
}

inline std::string u8(unsigned v)
{
    char b[4];
    std::snprintf(b, sizeof(b), "%02X", v & 0xFFu);
    return std::string(b);
}

inline std::string u16le(unsigned v)
{
    char b[8];
    std::snprintf(b, sizeof(b), "%02X %02X", v & 0xFFu, (v >> 8) & 0xFFu);
    return std::string(b);
}

// Object portion of a request = everything after the 2-byte application header (ctl, fc).
inline std::string objectPortion(const std::string& request)
{
    const auto t = toks(request);
    std::string s;
    for (size_t i = 2; i < t.size(); ++i)
        s += (i == 2 ? "" : " ") + t[i];
    return s;
}

// ----- DNP3 link-frame wire model -------------------------------------------------------
// A DNP3 link frame carries `u` bytes after the 8-octet link header + 2 header-CRC octets:
// the transport octet + application fragment, split into data blocks of <=16 octets each,
// with a 2-octet CRC after every block.
//   link_size(u) = 10 + u + 2*ceil(u/16)
inline int linkSize(int u)
{
    return 10 + u + 2 * static_cast<int>(std::ceil(u / 16.0));
}

// Completed-block boundary offsets within a link frame carrying `u` post-link bytes:
// after the 10-octet header, then after each (16 data + 2 CRC) block, then the residual.
inline std::vector<int> crcBoundaries(int u)
{
    std::vector<int> b;
    b.push_back(10); // end of link header (8 hdr + 2 header CRC)
    int off = 10, rem = u;
    while (rem > 0)
    {
        const int data = rem >= 16 ? 16 : rem;
        off += data + 2; // data block + its CRC
        b.push_back(off);
        rem -= data;
    }
    return b; // last entry == linkSize(u)
}

// ----- SBO echo/request per-object status walker ----------------------------------------
// Walks EVERY object across ALL G12V1 (0C 01) headers, supporting qualifiers 0x17 (1-byte
// count + 1-byte index prefix) and 0x28 (2-byte count + 2-byte index prefix). Returns the
// (index, statusByte) of every object. A request (no per-object status echoed back) still
// parses; the 11th CROB byte is the status field the outstation fills in the echo.
struct ObjStatus
{
    int index;
    std::string status;
};

inline std::vector<ObjStatus> parseSboEcho(const std::string& echo)
{
    const auto t = toks(echo);
    std::vector<ObjStatus> out;
    size_t i = 4; // skip ctl, fc(81), IIN(2) for a response echo
    while (i + 3 <= t.size())
    {
        // header: group var qual
        const std::string q = t[i + 2];
        i += 3;
        int cnt = 0, idxBytes = 0;
        if (q == "28")
        {
            cnt = hb(t[i]) | (hb(t[i + 1]) << 8);
            i += 2;
            idxBytes = 2;
        }
        else if (q == "17")
        {
            cnt = hb(t[i]);
            i += 1;
            idxBytes = 1;
        }
        else
        {
            break;
        }
        for (int c = 0; c < cnt; ++c)
        {
            const int idx = (idxBytes == 2) ? (hb(t[i]) | (hb(t[i + 1]) << 8)) : hb(t[i]);
            i += idxBytes;
            // CROB body is 11 bytes: code count on(4) off(4) status(1); status is the last.
            out.push_back({idx, t[i + 10]});
            i += 11;
        }
    }
    return out;
}

// Count the number of G12V1 (0C 01) object headers in a request/echo. "1" proves a single
// shared header (native CommandSet with one Add); ">1" would be repeated headers.
inline int countG12Headers(const std::string& hex)
{
    const auto t = toks(hex);
    int n = 0;
    for (size_t i = 0; i + 1 < t.size(); ++i)
        if (t[i] == "0C" && t[i + 1] == "01")
            ++n;
    return n;
}

inline std::string statusName(const std::string& s)
{
    switch (hb(s))
    {
    case 0:
        return "SUCCESS";
    case 2:
        return "NO_SELECT";
    case 4:
        return "NOT_SUPPORTED";
    case 6:
        return "HARDWARE_ERROR";
    default:
        return "0x" + s;
    }
}

} // namespace np

#endif // NATIVE_PARITY_HELPERS_H
