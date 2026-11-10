#pragma once

// Minimal DNS wire-format support (RFC 1035): enough to read queries and
// responses, follow CNAME chains, and synthesize "blocked" replies.

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace pithing::dns {

inline constexpr uint16_t kTypeA = 1;
inline constexpr uint16_t kTypeCname = 5;
inline constexpr uint16_t kTypeAaaa = 28;
inline constexpr uint16_t kTypeHttps = 65;
inline constexpr uint16_t kClassIn = 1;

struct Question {
  std::string name;  // lowercase, dotted, no trailing dot ("" is the root)
  uint16_t type = 0;
  uint16_t qclass = kClassIn;
};

struct Record {
  std::string name;
  uint16_t type = 0;
  uint16_t rclass = kClassIn;
  uint32_t ttl = 0;
  std::vector<uint8_t> rdata;  // raw; names inside may be compressed, so see `target`
  std::string target;          // decoded target name, set only for CNAME records
};

struct Message {
  uint16_t id = 0;
  bool is_response = false;
  uint8_t opcode = 0;
  bool authoritative = false;
  bool truncated = false;
  bool recursion_desired = false;
  bool recursion_available = false;
  uint8_t rcode = 0;
  std::vector<Question> questions;
  std::vector<Record> answers;  // authority/additional sections are not parsed
};

// Parses a complete message. Returns nullopt for anything malformed or
// truncated (bad lengths, compression loops, over-long names, ...). Never
// reads out of bounds, whatever the input.
std::optional<Message> parse(std::span<const uint8_t> wire);

// Builds a standard recursive query for one name. Returns an empty vector if
// the name cannot be encoded (empty label, label > 63 bytes, name > 253).
std::vector<uint8_t> build_query(std::string_view name, uint16_t type, uint16_t id = 0);

enum class BlockMode {
  NxDomain,  // "this name does not exist"
  NullIp,    // A -> 0.0.0.0, AAAA -> ::, every other type -> empty NOERROR
};

// Builds the reply for a blocked query. Echoes the id, opcode, RD flag and
// first question. Returns an empty vector if `query` has no question or its
// name cannot be re-encoded.
std::vector<uint8_t> build_blocked_response(const Message& query, BlockMode mode);

}  // namespace pithing::dns
