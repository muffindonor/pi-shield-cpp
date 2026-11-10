#include <string>

#include "blocklist/domain.hpp"
#include "blocklist/domain_set.hpp"
#include "test.hpp"

using namespace pithing;

namespace {

// Returns the normalized name, or a marker string if it was rejected. Avoids
// dereferencing a temporary optional inside CHECK_EQ.
std::string norm(std::string_view in, bool require_dot = true) {
  auto r = normalize_hostname(in, require_dot);
  return r ? *r : std::string("<rejected>");
}

}  // namespace

TEST(domain_normalize_accepts_and_canonicalizes) {
  CHECK_EQ(norm("Ads.Example.COM."), std::string("ads.example.com"));
  CHECK_EQ(norm("_dmarc.example.com"), std::string("_dmarc.example.com"));
  CHECK_EQ(norm("xn--bcher-kva.example"), std::string("xn--bcher-kva.example"));
  CHECK_EQ(norm(std::string(63, 'a') + ".com"), std::string(63, 'a') + ".com");
}

TEST(domain_normalize_rejects_non_hostnames) {
  CHECK(!normalize_hostname(""));
  CHECK(!normalize_hostname("."));
  CHECK(!normalize_hostname("a..b.com"));
  CHECK(!normalize_hostname(".example.com"));
  CHECK(!normalize_hostname("exa mple.com"));
  CHECK(!normalize_hostname("*.example.com"));
  CHECK(!normalize_hostname("example.com/path"));
  CHECK(!normalize_hostname("bücher.example"));
  CHECK(!normalize_hostname("127.0.0.1"));  // an IP address, not a name
  CHECK(!normalize_hostname(std::string(64, 'a') + ".com"));
  CHECK(!normalize_hostname(std::string(254, 'a')));
}

TEST(domain_normalize_single_label_policy) {
  CHECK(!normalize_hostname("localhost"));
  CHECK(!normalize_hostname("com"));
  CHECK_EQ(norm("localhost", /*require_dot=*/false), std::string("localhost"));
}

TEST(domain_set_matches_domain_and_subdomains) {
  DomainSet set;
  set.add("example.com");
  set.add("ads.tracker.net");
  set.finalize();

  CHECK_EQ(std::string(*set.match("example.com")), std::string("example.com"));
  CHECK_EQ(std::string(*set.match("www.example.com")), std::string("example.com"));
  CHECK_EQ(std::string(*set.match("a.b.c.example.com")), std::string("example.com"));
  CHECK_EQ(std::string(*set.match("x.ads.tracker.net")), std::string("ads.tracker.net"));
}

TEST(domain_set_does_not_match_partial_labels_or_parents) {
  DomainSet set;
  set.add("example.com");
  set.add("ads.tracker.net");
  set.finalize();

  CHECK(!set.match("notexample.com"));          // suffix of the string, not of the labels
  CHECK(!set.match("example.com.evil.org"));    // rule is a prefix, not a suffix
  CHECK(!set.match("tracker.net"));             // parent of a rule is not covered
  CHECK(!set.match("com"));
  CHECK(!set.match(""));
}

TEST(domain_set_prefers_the_most_specific_rule) {
  DomainSet set;
  set.add("example.com");
  set.add("cdn.example.com");
  set.finalize();
  CHECK_EQ(std::string(*set.match("img.cdn.example.com")), std::string("cdn.example.com"));
}

TEST(domain_set_deduplicates_and_can_grow_after_finalize) {
  DomainSet set;
  CHECK(set.empty());
  set.finalize();
  CHECK(!set.match("example.com"));

  for (int i = 0; i < 3; ++i) set.add("example.com");
  set.add("a.org");
  set.finalize();
  CHECK_EQ(set.size(), size_t{2});

  set.add("b.org");
  set.finalize();
  CHECK_EQ(set.size(), size_t{3});
  CHECK(set.match("www.b.org"));
  CHECK(set.match("a.org"));
}

TEST(domain_set_handles_many_entries) {
  DomainSet set;
  for (int i = 0; i < 20000; ++i) set.add("host" + std::to_string(i) + ".tracker" + std::to_string(i % 97) + ".net");
  set.finalize();
  CHECK_EQ(set.size(), size_t{20000});
  CHECK(set.match("www.host19999.tracker" + std::to_string(19999 % 97) + ".net"));
  CHECK(!set.match("host19999.tracker0.net"));  // right host number, wrong tracker number
}
