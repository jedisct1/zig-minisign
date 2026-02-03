#ifndef MINIZIGN_H
#define MINIZIGN_H

#include <stdint.h>
#include <stddef.h>
#ifdef _WIN32
#include <wchar.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

int32_t minisign_verify(
    const uint8_t data,
    size_t data_size,
    const char* public_key_str,
    const char* signature_str);

int32_t minisign_verify_file(
    const char* data_file,
    const char* public_key_file,
    const char* signature_file);

#ifdef _WIN32
int32_t minisign_verify_file_wide(
    const wchar_t* data_file,
    const wchar_t* public_key_file,
    const wchar_t* signature_file);
#endif

#ifdef __cplusplus
}
#endif

#endif // MINIZIGN_H
