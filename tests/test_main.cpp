#include "test.hpp"

int main() {
  for (const auto& c : pt_test::registry()) {
    const int before = pt_test::failures();
    c.fn();
    std::cout << (pt_test::failures() == before ? "  ok    " : "  FAIL  ") << c.name << "\n";
  }
  std::cout << pt_test::registry().size() << " tests, " << pt_test::failures() << " failed checks\n";
  return pt_test::failures() == 0 ? 0 : 1;
}
