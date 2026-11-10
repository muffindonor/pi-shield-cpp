#include "blocklist/filter.hpp"

#include "blocklist/domain.hpp"

namespace pithing {

bool Filter::add_block(std::string_view domain) {
  auto d = normalize_hostname(domain);
  if (!d) return false;
  block_.add(*d);
  return true;
}

bool Filter::add_allow(std::string_view domain) {
  auto d = normalize_hostname(domain);
  if (!d) return false;
  allow_.add(*d);
  return true;
}

ListStats Filter::load_list(std::string_view text) {
  return parse_list(
      text, [this](std::string_view d) { block_.add(d); }, [this](std::string_view d) { allow_.add(d); });
}

void Filter::finalize() {
  block_.finalize();
  allow_.finalize();
}

Verdict Filter::check(std::string_view domain) const {
  if (allow_.match(domain)) return {};
  if (auto rule = block_.match(domain)) return {true, std::string(*rule), {}};
  return {};
}

Verdict Filter::check_response(const dns::Message& response) const {
  if (!response.questions.empty() && allow_.match(response.questions.front().name)) return {};

  for (const dns::Record& record : response.answers) {
    if (record.type != dns::kTypeCname) continue;
    Verdict v = check(record.target);
    if (v.blocked) {
      v.cname = record.target;
      return v;
    }
  }
  return {};
}

}  // namespace pithing
