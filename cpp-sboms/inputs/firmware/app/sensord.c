/* sensord: device daemon for the sample firmware (static cJSON + expat, dynamic zlib + OpenSSL) */
#include <stdio.h>
#include <string.h>
#include <zlib.h>
#include <expat.h>
#include <openssl/sha.h>
#include <openssl/opensslv.h>
#include "cJSON.h"
int main(void) {
  unsigned char d[SHA256_DIGEST_LENGTH]; SHA256((const unsigned char *)"x", 1, d);
  cJSON *c = cJSON_Parse("{\"sensor\":\"t1\"}"); XML_Parser p = XML_ParserCreate(NULL);
  printf("sensord 3.1.0 zlib %s %s cJSON %s %s\n", zlibVersion(), OPENSSL_VERSION_TEXT, cJSON_Version(), XML_ExpatVersion());
  XML_ParserFree(p); cJSON_Delete(c); return 0;
}
