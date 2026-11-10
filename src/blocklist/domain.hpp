#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace pithing {

// Canonicalizes a hostname for use in rules: lowercase, one trailing dot
// removed. Returns nullopt if it is not a plain ASCII hostname (allowed
// characters: a-z 0-9 - _ .), has an empty or over-long label, exceeds 253
// bytes, or ends in an all-numeric label (which is an IP address, not a name).
// With `require_dot`, single-label names like "localhost" are rejected too;
// blocklists should never contain a bare TLD.
std::optional<std::string> normalize_hostname(std::string_view in, bool require_dot = true);

}  // namespace pithing
