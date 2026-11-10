#include <string>
#include <vector>

#include "blocklist/list_parser.hpp"
#include "test.hpp"

using namespace pithing;

namespace {

struct Parsed {
  std::vector<std::string> block;
  std::vector<std::string> allow;
  ListStats stats;
};

Parsed parse(std::string_view text) {
  Parsed p;
  p.stats = parse_list(
      text, [&](std::string_view d) { p.block.emplace_back(d); },
      [&](std::string_view d) { p.allow.emplace_back(d); });
  return p;
}

using List = std::vector<std::string>;

}  // namespace

TEST(list_hosts_format) {
  const Parsed p = parse(
      "# a comment\n"
      "\n"
      "127.0.0.1 localhost\n"
      "::1 localhost ip6-localhost\n"
      "0.0.0.0 ads.example.com\n"
      "0.0.0.0 Tracker.NET  # inline comment\n"
      "127.0.0.1 a.com b.com\n");
  CHECK(p.block == (List{"ads.example.com", "tracker.net", "a.com", "b.com"}));
  CHECK(p.allow.empty());
  CHECK_EQ(p.stats.block, size_t{4});
  CHECK_EQ(p.stats.ignored, size_t{3});  // localhost, localhost, ip6-localhost
}

TEST(list_crlf_line_endings_and_no_trailing_newline) {
  const Parsed p = parse("0.0.0.0 a.com\r\n0.0.0.0 b.com\r\nc.com");
  CHECK(p.block == (List{"a.com", "b.com", "c.com"}));
}

TEST(list_plain_domain_format) {
  const Parsed p = parse("ads.example.com\n  tracker.net  \n0.0.0.0\nnot a domain at all\n");
  CHECK(p.block == (List{"ads.example.com", "tracker.net"}));
  CHECK_EQ(p.stats.ignored, size_t{2});  // a bare IP, and a line whose first word is not an IP
}

TEST(list_adblock_format) {
  const Parsed p = parse(
      "[Adblock Plus 2.0]\n"
      "! Title: test\n"
      "||ads.example.com^\n"
      "||Tracker.NET^$important\n"
      "||thirdparty.com^$third-party\n"
      "||example.org/ads/banner\n"
      "||wild*.com^\n"
      "@@||good.example.com^\n"
      "@@/ads/allowed.js\n"
      "example.com##.banner\n"
      "plain-domain.org\n"
      "/regex/\n");
  CHECK(p.block == (List{"ads.example.com", "tracker.net", "plain-domain.org"}));
  CHECK(p.allow == (List{"good.example.com"}));
  // third-party option, path, wildcard, non-|| allow rule, cosmetic rule
  CHECK_EQ(p.stats.unsupported, size_t{5});
  CHECK_EQ(p.stats.ignored, size_t{1});  // "/regex/"
}

TEST(list_hash_handling_distinguishes_comments_from_cosmetic_rules) {
  const Parsed p = parse(
      "## Section header ##\n"
      "example.com##.ad\n"
      "example.net#@#.ad\n"
      "0.0.0.0 keep.com #comment\n");
  CHECK(p.block == (List{"keep.com"}));
  CHECK_EQ(p.stats.unsupported, size_t{2});
}

TEST(list_garbage_does_not_crash_or_block_anything) {
  const Parsed p = parse(std::string("\0\0\xff\xfe||\n@@\n||^\n^\n$\n|\n||.com^\n", 30));
  CHECK(p.block.empty());
  CHECK(p.allow.empty());
}

TEST(list_empty_input) {
  const Parsed p = parse("");
  CHECK(p.block.empty());
  CHECK_EQ(p.stats.block + p.stats.allow + p.stats.unsupported + p.stats.ignored, size_t{0});
}
