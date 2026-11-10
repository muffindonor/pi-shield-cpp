#pragma once

#include <string>
#include <string_view>

#include "blocklist/domain_set.hpp"
#include "blocklist/list_parser.hpp"
#include "dns/message.hpp"

namespace pithing {

struct Verdict {
  bool blocked = false;
  std::string rule;   // the blocklist entry that matched
  std::string cname;  // set when the block came from a CNAME target in the answer (cloaking)
};

// Block + allow rules. An allow rule always wins over a block rule, and both
// cover subdomains: blocking "example.com" blocks "a.b.example.com" too.
class Filter {
 public:
  // Both return false (and add nothing) if `domain` is not a valid hostname.
  bool add_block(std::string_view domain);
  bool add_allow(std::string_view domain);

  // Adds every usable rule in a hosts / domain / Adblock list.
  ListStats load_list(std::string_view text);

  // Call after adding rules and before check().
  void finalize();

  size_t block_count() const { return block_.size(); }
  size_t allow_count() const { return allow_.size(); }

  // `domain` must be lowercase with no trailing dot (dns::parse produces that).
  Verdict check(std::string_view domain) const;

  // Checks a response for CNAME cloaking: a harmless-looking name that is
  // really an alias for a tracker. The query name itself is not re-checked
  // (check() it before forwarding); an allow rule on the query name overrides
  // a blocked CNAME target.
  Verdict check_response(const dns::Message& response) const;

 private:
  DomainSet block_;
  DomainSet allow_;
};

}  // namespace pithing
