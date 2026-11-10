#include "blocklist/domain.hpp"

namespace pithing {

std::optional<std::string> normalize_hostname(std::string_view in, bool require_dot) {
  if (!in.empty() && in.back() == '.') in.remove_suffix(1);
  if (in.empty() || in.size() > 253) return std::nullopt;

  std::string out;
  out.reserve(in.size());
  size_t label_len = 0;
  bool last_label_all_digits = true;
  bool has_dot = false;

  for (const char raw : in) {
    char c = raw;
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    if (c == '.') {
      if (label_len == 0) return std::nullopt;
      has_dot = true;
      label_len = 0;
      last_label_all_digits = true;
    } else {
      const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
      if (!ok) return std::nullopt;
      if (++label_len > 63) return std::nullopt;
      if (c < '0' || c > '9') last_label_all_digits = false;
    }
    out.push_back(c);
  }

  if (label_len == 0) return std::nullopt;  // cannot happen after the trailing-dot strip, but be explicit
  if (last_label_all_digits) return std::nullopt;
  if (require_dot && !has_dot) return std::nullopt;
  return out;
}

}  // namespace pithing
