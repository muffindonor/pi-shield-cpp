#include "blocklist/list_parser.hpp"

#include <string>
#include <vector>

#include "blocklist/domain.hpp"

namespace pithing {
namespace {

bool is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v'; }

std::string_view trim(std::string_view s) {
  while (!s.empty() && is_space(s.front())) s.remove_prefix(1);
  while (!s.empty() && is_space(s.back())) s.remove_suffix(1);
  return s;
}

bool is_domain_char(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
         c == '_' || c == '.';
}

// "127.0.0.1", "0.0.0.0", "::1", "::" ...
bool is_ip_like(std::string_view token) {
  if (token.find(':') != std::string_view::npos) return true;
  int dots = 0;
  for (const char c : token) {
    if (c == '.') {
      ++dots;
    } else if (c < '0' || c > '9') {
      return false;
    }
  }
  return dots == 3;
}

std::vector<std::string_view> split_tokens(std::string_view line) {
  std::vector<std::string_view> tokens;
  size_t i = 0;
  while (i < line.size()) {
    while (i < line.size() && is_space(line[i])) ++i;
    const size_t start = i;
    while (i < line.size() && !is_space(line[i])) ++i;
    if (i > start) tokens.push_back(line.substr(start, i - start));
  }
  return tokens;
}

enum class AdblockResult { Domain, Unsupported, Ignored };

// `rest` is the rule text after the leading "||". Only the pure form
// "domain^" (optionally with $important / $all) can be expressed in DNS.
AdblockResult parse_adblock_domain(std::string_view rest, std::string& domain_out) {
  size_t n = 0;
  while (n < rest.size() && is_domain_char(rest[n])) ++n;
  std::string_view tail = rest.substr(n);

  if (!tail.empty()) {
    if (tail.front() != '^') return AdblockResult::Unsupported;  // path, wildcard, port, ...
    tail.remove_prefix(1);
    if (!tail.empty() && tail != "$important" && tail != "$all") return AdblockResult::Unsupported;
  }

  auto domain = normalize_hostname(rest.substr(0, n));
  if (!domain) return AdblockResult::Ignored;
  domain_out = std::move(*domain);
  return AdblockResult::Domain;
}

}  // namespace

ListStats parse_list(std::string_view text, const DomainSink& on_block, const DomainSink& on_allow) {
  ListStats stats;

  size_t start = 0;
  while (start <= text.size()) {
    const size_t nl = text.find('\n', start);
    std::string_view line = text.substr(start, nl == std::string_view::npos ? std::string_view::npos : nl - start);
    start = nl == std::string_view::npos ? text.size() + 1 : nl + 1;

    line = trim(line);
    if (line.empty()) continue;
    const char first = line.front();
    if (first == '!' || first == '#' || first == '[') continue;  // comments and "[Adblock Plus 2.0]"

    // Adblock rules: "||domain^" blocks, "@@||domain^" allows.
    bool allow = false;
    if (line.starts_with("@@")) {
      allow = true;
      line.remove_prefix(2);
      if (!line.starts_with("||")) {
        ++stats.unsupported;
        continue;
      }
    }
    if (line.starts_with("||")) {
      std::string domain;
      switch (parse_adblock_domain(line.substr(2), domain)) {
        case AdblockResult::Domain:
          if (allow) {
            on_allow(domain);
            ++stats.allow;
          } else {
            on_block(domain);
            ++stats.block;
          }
          break;
        case AdblockResult::Unsupported: ++stats.unsupported; break;
        case AdblockResult::Ignored: ++stats.ignored; break;
      }
      continue;
    }

    // Everything else is a hosts line or a bare domain. A '#' glued to the
    // text before it ("example.com##.ad") is a cosmetic rule; a '#' after
    // whitespace is an inline comment.
    const size_t hash = line.find('#');
    if (hash != std::string_view::npos) {
      if (hash > 0 && !is_space(line[hash - 1])) {
        ++stats.unsupported;
        continue;
      }
      line = trim(line.substr(0, hash));
      if (line.empty()) continue;
    }

    const std::vector<std::string_view> tokens = split_tokens(line);
    size_t first_domain = 0;
    if (tokens.size() > 1) {
      if (!is_ip_like(tokens[0])) {
        ++stats.ignored;
        continue;
      }
      first_domain = 1;
    }
    for (size_t i = first_domain; i < tokens.size(); ++i) {
      if (auto domain = normalize_hostname(tokens[i])) {
        on_block(*domain);
        ++stats.block;
      } else {
        ++stats.ignored;
      }
    }
  }
  return stats;
}

}  // namespace pithing
