#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace pithing {

// A set of domain names that answers "is this name, or any parent of it, in
// the set?". Built for big blocklists on a small machine: all names live in
// one contiguous buffer, sorted, with an 8-byte index entry each, so a million
// rules cost roughly 30 MB and a lookup is a handful of binary searches.
//
// Usage: add() any number of normalized (lowercase, no trailing dot) names,
// call finalize(), then match(). Adding more later is fine, but finalize()
// must be called again before the next match().
class DomainSet {
 public:
  void add(std::string_view domain);
  void finalize();

  size_t size() const { return entries_.size(); }  // deduplicated after finalize()
  bool empty() const { return entries_.empty(); }

  // Returns the most specific rule that covers `domain`: the domain itself,
  // or failing that its nearest parent that is in the set. The returned view
  // points into `domain`, so it is valid as long as `domain` is.
  // `domain` must be lowercase with no trailing dot.
  std::optional<std::string_view> match(std::string_view domain) const;

 private:
  struct Entry {
    uint32_t offset;
    uint8_t length;
  };

  std::string_view view(const Entry& e) const { return std::string_view(blob_).substr(e.offset, e.length); }
  bool contains(std::string_view key) const;

  std::string blob_;
  std::vector<Entry> entries_;
  bool dirty_ = false;
};

}  // namespace pithing
