// sensorhub-gateway: sample CMake-only product for SBOM tests (no package manager)
#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <expat.h>
#include <zlib.h>
extern "C" {
#include "cJSON.h"
}
int main() {
  nlohmann::json cfg = {{"device", "sensorhub"}, {"version", "2.4.0"}};
  cJSON *c = cJSON_Parse("{\"ok\":true}");
  XML_Parser p = XML_ParserCreate(nullptr);
  fmt::print("sensorhub-gateway {} zlib {} expat {} cjson {}\n",
             cfg["version"].get<std::string>(), zlibVersion(), XML_ExpatVersion(), cJSON_Version());
  XML_ParserFree(p); cJSON_Delete(c);
  return 0;
}
