#include <string>

#include "blocklist/filter.hpp"
#include "test.hpp"
#include "wire.hpp"

using namespace pithing;

TEST(filter_blocks_domain_and_subdomains) {
  Filter f;
  CHECK(f.add_block("Example.com"));
  f.finalize();

  const Verdict v = f.check("www.example.com");
  CHECK(v.blocked);
  CHECK_EQ(v.rule, std::string("example.com"));
  CHECK(v.cname.empty());
  CHECK(!f.check("example.org").blocked);
  CHECK(!f.check("notexample.com").blocked);
}

TEST(filter_allow_overrides_block) {
  Filter f;
  f.add_block("example.com");
  f.add_allow("cdn.example.com");
  f.finalize();

  CHECK(f.check("www.example.com").blocked);
  CHECK(!f.check("cdn.example.com").blocked);
  CHECK(!f.check("img.cdn.example.com").blocked);
}

TEST(filter_rejects_invalid_rules) {
  Filter f;
  CHECK(!f.add_block("localhost"));
  CHECK(!f.add_block("*.example.com"));
  CHECK(!f.add_allow(""));
  f.finalize();
  CHECK_EQ(f.block_count(), size_t{0});
  CHECK_EQ(f.allow_count(), size_t{0});
}

TEST(filter_loads_lists) {
  Filter f;
  const ListStats s = f.load_list(
      "0.0.0.0 ads.example.com\n"
      "||tracker.net^\n"
      "@@||ok.tracker.net^\n");
  f.finalize();
  CHECK_EQ(s.block, size_t{2});
  CHECK_EQ(s.allow, size_t{1});
  CHECK(f.check("ads.example.com").blocked);
  CHECK(f.check("x.tracker.net").blocked);
  CHECK(!f.check("ok.tracker.net").blocked);
}

TEST(filter_uncovers_cname_cloaking) {
  Filter f;
  f.add_block("adtracker.net");
  f.finalize();

  // The name the user asked for is clean, so a DNS-only blocker lets it through...
  CHECK(!f.check("www.shop.com").blocked);

  // ...but the answer reveals it is an alias for a tracker.
  const auto response = dns::parse(wire::cname_response("www.shop.com", "metrics.adtracker.net"));
  CHECK(response.has_value());
  if (!response) return;
  const Verdict v = f.check_response(*response);
  CHECK(v.blocked);
  CHECK_EQ(v.rule, std::string("adtracker.net"));
  CHECK_EQ(v.cname, std::string("metrics.adtracker.net"));
}

TEST(filter_clean_cname_is_not_blocked) {
  Filter f;
  f.add_block("adtracker.net");
  f.finalize();
  const auto response = dns::parse(wire::cname_response("www.shop.com", "shop.cdn-provider.net"));
  CHECK(response.has_value());
  if (!response) return;
  CHECK(!f.check_response(*response).blocked);
}

TEST(filter_allow_on_query_name_overrides_blocked_cname) {
  Filter f;
  f.add_block("adtracker.net");
  f.add_allow("shop.com");
  f.finalize();
  const auto response = dns::parse(wire::cname_response("www.shop.com", "metrics.adtracker.net"));
  CHECK(response.has_value());
  if (!response) return;
  CHECK(!f.check_response(*response).blocked);
}

TEST(filter_allow_on_cname_target_overrides_block) {
  Filter f;
  f.add_block("adtracker.net");
  f.add_allow("static.adtracker.net");
  f.finalize();
  const auto response = dns::parse(wire::cname_response("www.shop.com", "static.adtracker.net"));
  CHECK(response.has_value());
  if (!response) return;
  CHECK(!f.check_response(*response).blocked);
}
