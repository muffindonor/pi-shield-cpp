#include "dns/message.hpp"

namespace pithing::dns {
namespace {

constexpr size_t kHeaderSize = 12;
constexpr size_t kMaxWireNameLength = 255;
constexpr size_t kMaxLabelLength = 63;
constexpr int kMaxPointerJumps = 16;
constexpr uint32_t kBlockedTtl = 60;

uint16_t load16(std::span<const uint8_t> d, size_t pos) {
  return static_cast<uint16_t>((d[pos] << 8) | d[pos + 1]);
}

bool read16(std::span<const uint8_t> d, size_t& pos, uint16_t& out) {
  if (pos + 2 > d.size()) return false;
  out = load16(d, pos);
  pos += 2;
  return true;
}

bool read32(std::span<const uint8_t> d, size_t& pos, uint32_t& out) {
  if (pos + 4 > d.size()) return false;
  out = (static_cast<uint32_t>(d[pos]) << 24) | (static_cast<uint32_t>(d[pos + 1]) << 16) |
        (static_cast<uint32_t>(d[pos + 2]) << 8) | d[pos + 3];
  pos += 4;
  return true;
}

// Reads a (possibly compressed) name starting at `pos`. On success `pos` is
// left just past the name as it appears at the original position, i.e. after
// the first compression pointer if there was one.
std::optional<std::string> read_name(std::span<const uint8_t> msg, size_t& pos) {
  std::string name;
  size_t cur = pos;
  bool jumped = false;
  int jumps = 0;
  size_t wire_len = 1;  // the terminating zero byte

  while (true) {
    if (cur >= msg.size()) return std::nullopt;
    const uint8_t len = msg[cur];

    if (len == 0) {
      if (!jumped) pos = cur + 1;
      return name;
    }
    if ((len & 0xC0) == 0xC0) {
      if (cur + 1 >= msg.size()) return std::nullopt;
      if (!jumped) pos = cur + 2;
      jumped = true;
      if (++jumps > kMaxPointerJumps) return std::nullopt;
      cur = (static_cast<size_t>(len & 0x3F) << 8) | msg[cur + 1];
      continue;
    }
    if ((len & 0xC0) != 0) return std::nullopt;  // 0x40 / 0x80 label types are reserved

    if (cur + 1 + len > msg.size()) return std::nullopt;
    wire_len += static_cast<size_t>(len) + 1;
    if (wire_len > kMaxWireNameLength) return std::nullopt;

    if (!name.empty()) name.push_back('.');
    for (size_t i = 0; i < len; ++i) {
      char c = static_cast<char>(msg[cur + 1 + i]);
      if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
      name.push_back(c);
    }
    cur += 1 + static_cast<size_t>(len);
  }
}

void put16(std::vector<uint8_t>& out, uint16_t v) {
  out.push_back(static_cast<uint8_t>(v >> 8));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}

void put32(std::vector<uint8_t>& out, uint32_t v) {
  put16(out, static_cast<uint16_t>(v >> 16));
  put16(out, static_cast<uint16_t>(v & 0xFFFF));
}

bool put_name(std::vector<uint8_t>& out, std::string_view name) {
  if (name.empty()) {
    out.push_back(0);
    return true;
  }
  if (name.size() > kMaxWireNameLength - 2) return false;
  size_t start = 0;
  while (true) {
    const size_t dot = name.find('.', start);
    const std::string_view label =
        name.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start);
    if (label.empty() || label.size() > kMaxLabelLength) return false;
    out.push_back(static_cast<uint8_t>(label.size()));
    out.insert(out.end(), label.begin(), label.end());
    if (dot == std::string_view::npos) break;
    start = dot + 1;
  }
  out.push_back(0);
  return true;
}

}  // namespace

std::optional<Message> parse(std::span<const uint8_t> wire) {
  if (wire.size() < kHeaderSize) return std::nullopt;

  Message m;
  m.id = load16(wire, 0);
  const uint16_t flags = load16(wire, 2);
  m.is_response = (flags & 0x8000) != 0;
  m.opcode = static_cast<uint8_t>((flags >> 11) & 0x0F);
  m.authoritative = (flags & 0x0400) != 0;
  m.truncated = (flags & 0x0200) != 0;
  m.recursion_desired = (flags & 0x0100) != 0;
  m.recursion_available = (flags & 0x0080) != 0;
  m.rcode = static_cast<uint8_t>(flags & 0x0F);
  const uint16_t qdcount = load16(wire, 4);
  const uint16_t ancount = load16(wire, 6);

  size_t pos = kHeaderSize;
  for (uint16_t i = 0; i < qdcount; ++i) {
    Question q;
    auto name = read_name(wire, pos);
    if (!name) return std::nullopt;
    q.name = std::move(*name);
    if (!read16(wire, pos, q.type) || !read16(wire, pos, q.qclass)) return std::nullopt;
    m.questions.push_back(std::move(q));
  }

  for (uint16_t i = 0; i < ancount; ++i) {
    Record r;
    auto name = read_name(wire, pos);
    if (!name) return std::nullopt;
    r.name = std::move(*name);
    uint16_t rdlength = 0;
    if (!read16(wire, pos, r.type) || !read16(wire, pos, r.rclass) || !read32(wire, pos, r.ttl) ||
        !read16(wire, pos, rdlength)) {
      return std::nullopt;
    }
    if (pos + rdlength > wire.size()) return std::nullopt;
    const size_t rdata_end = pos + rdlength;
    r.rdata.assign(wire.begin() + static_cast<std::ptrdiff_t>(pos),
                   wire.begin() + static_cast<std::ptrdiff_t>(rdata_end));
    if (r.type == kTypeCname) {
      size_t rpos = pos;
      auto target = read_name(wire, rpos);
      if (!target || rpos > rdata_end) return std::nullopt;
      r.target = std::move(*target);
    }
    pos = rdata_end;
    m.answers.push_back(std::move(r));
  }
  return m;
}

std::vector<uint8_t> build_query(std::string_view name, uint16_t type, uint16_t id) {
  if (name.size() > 1 && name.back() == '.') name.remove_suffix(1);
  if (name == ".") name = {};

  std::vector<uint8_t> out;
  put16(out, id);
  put16(out, 0x0100);  // standard query, recursion desired
  put16(out, 1);
  put16(out, 0);
  put16(out, 0);
  put16(out, 0);
  if (!put_name(out, name)) return {};
  put16(out, type);
  put16(out, kClassIn);
  return out;
}

std::vector<uint8_t> build_blocked_response(const Message& query, BlockMode mode) {
  if (query.questions.empty()) return {};
  const Question& q = query.questions.front();
  const bool is_address = q.type == kTypeA || q.type == kTypeAaaa;
  const bool synthesize = mode == BlockMode::NullIp && is_address;

  uint16_t flags = 0x8000;                                           // QR: this is a response
  flags = static_cast<uint16_t>(flags | ((query.opcode & 0x0F) << 11));
  if (query.recursion_desired) flags |= 0x0100;
  flags |= 0x0080;                                                   // RA
  if (mode == BlockMode::NxDomain) flags |= 3;                       // NXDOMAIN

  std::vector<uint8_t> out;
  out.reserve(64);
  put16(out, query.id);
  put16(out, flags);
  put16(out, 1);
  put16(out, synthesize ? 1 : 0);
  put16(out, 0);
  put16(out, 0);
  if (!put_name(out, q.name)) return {};
  put16(out, q.type);
  put16(out, q.qclass);

  if (synthesize) {
    put16(out, 0xC00C);  // pointer back to the question name
    put16(out, q.type);
    put16(out, q.qclass);
    put32(out, kBlockedTtl);
    const size_t addr_len = q.type == kTypeA ? 4 : 16;
    put16(out, static_cast<uint16_t>(addr_len));
    out.insert(out.end(), addr_len, 0);
  }
  return out;
}

}  // namespace pithing::dns
