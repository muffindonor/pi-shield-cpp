#include "blocklist/domain_set.hpp"

#include <algorithm>
#include <cassert>

namespace pithing {

void DomainSet::add(std::string_view domain) {
  if (domain.empty() || domain.size() > 253) return;
  entries_.push_back({static_cast<uint32_t>(blob_.size()), static_cast<uint8_t>(domain.size())});
  blob_.append(domain);
  dirty_ = true;
}

void DomainSet::finalize() {
  std::sort(entries_.begin(), entries_.end(),
            [this](const Entry& a, const Entry& b) { return view(a) < view(b); });
  entries_.erase(std::unique(entries_.begin(), entries_.end(),
                             [this](const Entry& a, const Entry& b) { return view(a) == view(b); }),
                 entries_.end());

  // Rewrite the blob in sorted order without the duplicates' bytes.
  std::string compact;
  compact.reserve(blob_.size());
  for (Entry& e : entries_) {
    const std::string_view v = view(e);
    e.offset = static_cast<uint32_t>(compact.size());
    compact.append(v);
  }
  blob_ = std::move(compact);
  blob_.shrink_to_fit();
  entries_.shrink_to_fit();
  dirty_ = false;
}

bool DomainSet::contains(std::string_view key) const {
  const auto it = std::lower_bound(entries_.begin(), entries_.end(), key,
                                   [this](const Entry& e, std::string_view k) { return view(e) < k; });
  return it != entries_.end() && view(*it) == key;
}

std::optional<std::string_view> DomainSet::match(std::string_view domain) const {
  assert(!dirty_ && "DomainSet::finalize() must be called before match()");
  if (entries_.empty()) return std::nullopt;

  size_t pos = 0;
  while (true) {
    const std::string_view suffix = domain.substr(pos);
    if (contains(suffix)) return suffix;
    const size_t dot = domain.find('.', pos);
    if (dot == std::string_view::npos) return std::nullopt;
    pos = dot + 1;
  }
}

}  // namespace pithing
