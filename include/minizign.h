#ifndef MINIZIGN_H
#define MINIZIGN_H

/* You can customize this header (e.g define MINIZIGN_IMPORT) by
 * creating this file and putting it in your include path.
 *
 * ... or by putting extra stuff in your compiler command line :)
 */
#if __has_include(<minizign.tweaks.h>)
#include <minizign.tweaks.h>
#endif

/* If you're on Win32 and using the dll, you probably want to define
 * this to `__declspec(dllimport)` */
#ifndef MINIZIGN_IMPORT
#define MINIZIGN_IMPORT
#endif


#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct minizign_signature minizign_signature;
typedef struct minizign_public_key minizign_public_key;
typedef struct minizign_verifier minizign_verifier;

MINIZIGN_IMPORT minizign_signature* minizign_signature_create(
    const uint8_t* data,
    uint32_t dataLength,
    int32_t* errorOut);
MINIZIGN_IMPORT void minizign_signature_destroy(minizign_signature*);


MINIZIGN_IMPORT uintptr_t minizign_public_key_size();
MINIZIGN_IMPORT minizign_public_key* minizign_public_key_create_from_base64(
    const uint8_t* data,
    uint32_t dataLength,
    int32_t* errorOut);
MINIZIGN_IMPORT intptr_t minizign_public_key_decode_from_ssh(
    minizign_public_key* pksOut,
    uintptr_t pksOutLength,
    const uint8_t* lines,
    uintptr_t linesLength);
MINIZIGN_IMPORT void minizign_public_key_destroy(minizign_public_key*);

MINIZIGN_IMPORT minizign_verifier* minizign_verifier_create(
    const minizign_public_key*,
    const minizign_signature*,
    int32_t* errorOut);
MINIZIGN_IMPORT void minizign_verifier_update(
    minizign_verifier*,
    const uint8_t* data,
    uint32_t dataLength);
MINIZIGN_IMPORT intptr_t minizign_verifier_verify(
    minizign_verifier*);
MINIZIGN_IMPORT void minizign_verifier_destroy(minizign_verifier*);


#ifdef __cplusplus
}
#endif

#endif // MINIZIGN_H
