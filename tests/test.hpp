#pragma once

// A deliberately tiny test harness so the project has no dependencies.
//   TEST(name) { CHECK(cond); CHECK_EQ(a, b); }

#include <iostream>
#include <vector>

namespace pt_test {

struct Case {
  const char* name;
  void (*fn)();
};

inline std::vector<Case>& registry() {
  static std::vector<Case> r;
  return r;
}

inline int& failures() {
  static int f = 0;
  return f;
}

struct Registrar {
  Registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

}  // namespace pt_test

#define TEST(name)                                          \
  static void test_##name();                                \
  static pt_test::Registrar registrar_##name(#name, test_##name); \
  static void test_##name()

#define CHECK(expr)                                                                  \
  do {                                                                               \
    if (!(expr)) {                                                                   \
      ++pt_test::failures();                                                         \
      std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #expr "\n";     \
    }                                                                                \
  } while (0)

#define CHECK_EQ(a, b)                                                               \
  do {                                                                               \
    const auto& va_ = (a);                                                           \
    const auto& vb_ = (b);                                                           \
    if (!(va_ == vb_)) {                                                             \
      ++pt_test::failures();                                                         \
      std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK_EQ failed: " #a " == " #b \
                << "\n    left:  " << va_ << "\n    right: " << vb_ << "\n";          \
    }                                                                                \
  } while (0)
