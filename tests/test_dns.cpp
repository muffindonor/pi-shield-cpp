#include "dns/message.hpp"
#include "test.hpp"
#include "wire.hpp"

using namespace pithing::dns;

TEST(dns_query_roundtrip) {
  const auto wire = build_query("Example.COM", kTypeA, 0xBEEF);
  const auto m = parse(wire);
  CHECK(m.has_value());
  if (!m) return;
  CHECK_EQ(m->id, 0xBEEF);
  CHECK(!m->is_response);
  CHECK(m->recursion_desired);
  CHECK_EQ(m->questions.size(), size_t{1});
  CHECK_EQ(m->questions[0].name, std::string("example.com"));  // lowercased on parse
  CHECK_EQ(m->questions[0].type, kTypeA);
  CHECK_EQ(m->questions[0].qclass, kClassIn);
  CHECK(m->answers.empty());
}

TEST(dns_build_query_rejects_unencodable_names) {
  CHECK(build_query("a..b", kTypeA).empty());
  CHECK(build_query(std::string(64, 'a') + ".com", kTypeA).empty());
  CHECK(build_query(std::string(63, 'a') + ".com", kTypeA).size() > 12);
  CHECK(!build_query("example.com.", kTypeA).empty());  // one trailing dot is tolerated
}

TEST(dns_parse_cname_response) {
  const auto m = parse(wire::cname_response("www.shop.com", "metrics.adtracker.net"));
  CHECK(m.has_value());
  if (!m) return;
  CHECK(m->is_response);
  CHECK(m->recursion_available);
  CHECK_EQ(m->answers.size(), size_t{2});
  CHECK_EQ(m->answers[0].name, std::string("www.shop.com"));  // came via compression pointer
  CHECK_EQ(m->answers[0].type, kTypeCname);
  CHECK_EQ(m->answers[0].ttl, uint32_t{300});
  CHECK_EQ(m->answers[0].target, std::string("metrics.adtracker.net"));
  CHECK_EQ(m->answers[1].type, kTypeA);
  CHECK_EQ(m->answers[1].rdata.size(), size_t{4});
}

TEST(dns_parse_compression_inside_cname_rdata) {
  // CNAME rdata = label "tracker" + pointer to "example.com" (offset 16, inside the question).
  wire::Bytes b;
  b.u16(7).u16(0x8180).u16(1).u16(1).u16(0).u16(0);
  b.name("www.example.com").u16(1).u16(1);
  b.u16(0xC00C).u16(5).u16(1).u32(60).u16(10);
  b.u8(7).raw(std::string("tracker")).u16(0xC010);

  const auto m = parse(b.v);
  CHECK(m.has_value());
  if (!m) return;
  CHECK_EQ(m->answers.size(), size_t{1});
  CHECK_EQ(m->answers[0].target, std::string("tracker.example.com"));
}

TEST(dns_every_truncation_is_rejected_without_crashing) {
  const auto full = wire::cname_response("www.shop.com", "metrics.adtracker.net");
  for (size_t len = 0; len < full.size(); ++len) {
    const auto m = parse(std::span<const uint8_t>(full.data(), len));
    CHECK(!m.has_value());  // the header promises two answers, so any prefix is incomplete
  }
  CHECK(parse(full).has_value());
}

TEST(dns_compression_loops_are_rejected) {
  // Question name is a pointer to itself.
  wire::Bytes self;
  self.u16(1).u16(0x0100).u16(1).u16(0).u16(0).u16(0);
  self.u16(0xC00C).u16(1).u16(1);
  CHECK(!parse(self.v).has_value());

  // Two pointers that point at each other.
  wire::Bytes pair;
  pair.u16(1).u16(0x0100).u16(1).u16(0).u16(0).u16(0);
  pair.u16(0xC00E).u16(0xC00C).u16(1).u16(1);
  CHECK(!parse(pair.v).has_value());
}

TEST(dns_reserved_label_types_and_oversize_names_are_rejected) {
  wire::Bytes reserved;
  reserved.u16(1).u16(0x0100).u16(1).u16(0).u16(0).u16(0);
  reserved.u8(0x80).u8(0).u16(1).u16(1);
  CHECK(!parse(reserved.v).has_value());

  // 5 labels of 63 bytes = 320 bytes on the wire, over the 255 limit.
  wire::Bytes big;
  big.u16(1).u16(0x0100).u16(1).u16(0).u16(0).u16(0);
  for (int i = 0; i < 5; ++i) big.u8(63).raw(std::string(63, 'a'));
  big.u8(0).u16(1).u16(1);
  CHECK(!parse(big.v).has_value());
}

static Message parse_query_for(const char* name, uint16_t type) {
  auto m = parse(build_query(name, type, 0x4242));
  return m ? *m : Message{};
}

TEST(dns_blocked_nxdomain) {
  const Message q = parse_query_for("ads.example.com", kTypeA);
  const auto reply = build_blocked_response(q, BlockMode::NxDomain);
  const auto m = parse(reply);
  CHECK(m.has_value());
  if (!m) return;
  CHECK_EQ(m->id, 0x4242);
  CHECK(m->is_response);
  CHECK(m->recursion_desired);
  CHECK(m->recursion_available);
  CHECK_EQ(int{m->rcode}, 3);
  CHECK_EQ(m->questions.size(), size_t{1});
  CHECK_EQ(m->questions[0].name, std::string("ads.example.com"));
  CHECK(m->answers.empty());
}

TEST(dns_blocked_null_ip_for_a_and_aaaa) {
  for (const uint16_t type : {kTypeA, kTypeAaaa}) {
    const Message q = parse_query_for("ads.example.com", type);
    const auto m = parse(build_blocked_response(q, BlockMode::NullIp));
    CHECK(m.has_value());
    if (!m) return;
    CHECK_EQ(int{m->rcode}, 0);
    CHECK_EQ(m->answers.size(), size_t{1});
    CHECK_EQ(m->answers[0].name, std::string("ads.example.com"));
    CHECK_EQ(m->answers[0].type, type);
    CHECK_EQ(m->answers[0].ttl, uint32_t{60});
    CHECK_EQ(m->answers[0].rdata.size(), type == kTypeA ? size_t{4} : size_t{16});
    for (const uint8_t byte : m->answers[0].rdata) CHECK_EQ(int{byte}, 0);
  }
}

TEST(dns_blocked_null_ip_other_types_get_empty_noerror) {
  for (const uint16_t type : {uint16_t{16} /*TXT*/, kTypeHttps}) {
    const Message q = parse_query_for("ads.example.com", type);
    const auto m = parse(build_blocked_response(q, BlockMode::NullIp));
    CHECK(m.has_value());
    if (!m) return;
    CHECK_EQ(int{m->rcode}, 0);
    CHECK(m->answers.empty());
    CHECK_EQ(m->questions.size(), size_t{1});
  }
}

TEST(dns_blocked_response_needs_a_question) {
  CHECK(build_blocked_response(Message{}, BlockMode::NxDomain).empty());
}
