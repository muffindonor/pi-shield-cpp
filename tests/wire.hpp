#pragma once

// Helpers for hand-assembling DNS packets in tests, so the tests do not
// depend on the code that builds packets in src/.

#include <cstdint>
#include <string>
#include <vector>

namespace wire {

struct Bytes {
  std::vector<uint8_t> v;

  Bytes& u8(uint8_t x) {
    v.push_back(x);
    return *this;
  }
  Bytes& u16(uint16_t x) { return u8(static_cast<uint8_t>(x >> 8)).u8(static_cast<uint8_t>(x & 0xFF)); }
  Bytes& u32(uint32_t x) { return u16(static_cast<uint16_t>(x >> 16)).u16(static_cast<uint16_t>(x & 0xFFFF)); }
  Bytes& raw(const std::string& s) {
    v.insert(v.end(), s.begin(), s.end());
    return *this;
  }
  Bytes& raw(const std::vector<uint8_t>& b) {
    v.insert(v.end(), b.begin(), b.end());
    return *this;
  }
  // Uncompressed name: "a.bc" -> 1 'a' 2 'b' 'c' 0
  Bytes& name(const std::string& dotted) {
    size_t start = 0;
    while (start < dotted.size()) {
      size_t dot = dotted.find('.', start);
      if (dot == std::string::npos) dot = dotted.size();
      u8(static_cast<uint8_t>(dot - start));
      raw(dotted.substr(start, dot - start));
      start = dot + 1;
    }
    return u8(0);
  }
};

// A response to an A query for `qname`: one CNAME answer to `target`, then an
// A record for the target. The CNAME owner name is a compression pointer to
// the question (offset 12); the target is spelled out in full.
inline std::vector<uint8_t> cname_response(const std::string& qname, const std::string& target) {
  Bytes b;
  b.u16(0x1234).u16(0x8180).u16(1).u16(2).u16(0).u16(0);
  b.name(qname).u16(1).u16(1);

  Bytes rdata;
  rdata.name(target);
  b.u16(0xC00C).u16(5).u16(1).u32(300).u16(static_cast<uint16_t>(rdata.v.size())).raw(rdata.v);

  b.name(target).u16(1).u16(1).u32(300).u16(4).u8(1).u8(2).u8(3).u8(4);
  return b.v;
}

}  // namespace wire
