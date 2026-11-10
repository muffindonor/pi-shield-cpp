// pithing_check: load blocklists, then ask whether domains would be blocked.
//
//   pithing_check hosts.txt easylist.txt -- ads.example.com www.example.org
//   pithing_check hosts.txt < domains.txt        (one domain per line)

#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "blocklist/domain.hpp"
#include "blocklist/filter.hpp"

namespace {

bool read_file(const std::string& path, std::string& out) {
  std::ifstream in(path, std::ios::binary | std::ios::ate);
  if (!in) return false;
  out.resize(static_cast<size_t>(in.tellg()));
  in.seekg(0);
  in.read(out.data(), static_cast<std::streamsize>(out.size()));
  return in.gcount() == static_cast<std::streamsize>(out.size());
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> files;
  std::vector<std::string> domains;
  bool after_separator = false;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--") {
      after_separator = true;
    } else {
      (after_separator ? domains : files).push_back(arg);
    }
  }
  if (files.empty()) {
    std::cerr << "usage: pithing_check <list-file>... [-- <domain>...]\n"
                 "       (with no domains given, reads them from stdin)\n";
    return 2;
  }

  pithing::Filter filter;
  const auto t0 = std::chrono::steady_clock::now();
  for (const std::string& path : files) {
    std::string text;
    if (!read_file(path, text)) {
      std::cerr << "cannot read " << path << "\n";
      return 1;
    }
    const pithing::ListStats s = filter.load_list(text);
    std::cerr << path << ": block=" << s.block << " allow=" << s.allow << " unsupported=" << s.unsupported
              << " ignored=" << s.ignored << "\n";
  }
  filter.finalize();
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
  std::cerr << "loaded " << filter.block_count() << " block / " << filter.allow_count() << " allow rules in "
            << ms.count() << " ms\n";

  auto report = [&](const std::string& raw) {
    const auto domain = pithing::normalize_hostname(raw, /*require_dot=*/false);
    if (!domain) {
      std::cout << "INVALID " << raw << "\n";
      return;
    }
    const pithing::Verdict v = filter.check(*domain);
    if (v.blocked) {
      std::cout << "BLOCK " << *domain << "  (rule: " << v.rule << ")\n";
    } else {
      std::cout << "ALLOW " << *domain << "\n";
    }
  };

  if (!domains.empty()) {
    for (const std::string& d : domains) report(d);
  } else {
    std::string line;
    while (std::getline(std::cin, line)) {
      if (!line.empty() && line.back() == '\r') line.pop_back();
      if (!line.empty()) report(line);
    }
  }
  return 0;
}
