#include "include/minizign.h"

#include <fstream>
#include <print>
#include <string>
#include <memory>
#include <vector>

template<auto TDeleter>
struct CDeleter {
  static void operator()(auto p) {
    TDeleter(p);
  }
};
using unique_pkey = std::unique_ptr<minizign_public_key, CDeleter<&minizign_public_key_destroy>>;

std::vector<uint8_t> read_file(const auto path) {
  std::ifstream f(path, std::ios::binary | std::ios::ate);
  const auto size = f.tellg();
  f.seekg(0, std::ios::beg);

  std::vector<uint8_t> ret;
  ret.resize(size);

  f.read(reinterpret_cast<char*>(ret.data()), ret.size());

  return ret;
}

int main() {
  const auto pkeyBlob = read_file("key.pub");
  const auto contentBlob = read_file("LICENSE");
  const auto signatureBlob = read_file("LICENSE.sig");

  std::println("Pkey: {}", std::string_view { reinterpret_cast<const char*>(pkeyBlob.data()), pkeyBlob.size() });

  int32_t error {};
  const unique_pkey pkey { minizign_public_key_create_from_base64(pkeyBlob.data(), pkeyBlob.size(), &error) };
  if (!pkey) {
    std::println(stderr, "Failed to load pkey: {}", error);
    return EXIT_FAILURE;
  }
  std::print("Loaded public key");

  return 0;
}
