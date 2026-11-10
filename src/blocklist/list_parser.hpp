#pragma once

#include <cstddef>
#include <functional>
#include <string_view>

namespace pithing {

struct ListStats {
  size_t block = 0;        // domains that will be blocked
  size_t allow = 0;        // domains exempted from blocking (@@ rules)
  size_t unsupported = 0;  // valid-looking rules DNS cannot express: paths, wildcards,
                           // $options, cosmetic (##) rules. These need a proxy or a browser.
  size_t ignored = 0;      // junk, localhost entries, anything that is not a usable domain
};

using DomainSink = std::function<void(std::string_view)>;

// Parses a blocklist and reports each usable domain, already normalized.
// Understands three formats, mixed freely:
//   hosts file:  "0.0.0.0 ads.example.com [more.example.com ...]"  (# comments)
//   domain list: "ads.example.com"
//   Adblock:     "||ads.example.com^", "@@||ok.example.com^"  (! comments)
// Handles LF and CRLF line endings. Never throws on bad input.
ListStats parse_list(std::string_view text, const DomainSink& on_block, const DomainSink& on_allow);

}  // namespace pithing
