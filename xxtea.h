#ifndef __XXTEA_H__
#define __XXTEA_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <stdint.h>
#ifdef ENABLE_LUA_XXTEA

# include "lua.h"
# include "lauxlib.h"
struct lua_State;
int luaopen_xxtea( lua_State *L );

#endif /*ENABLE_LUA_XXTEA*/

#ifdef XXTEA_SIZE_64
typedef uint64_t xxtea_length_t;
#else
typedef uint32_t xxtea_length_t;
#endif /*XXTEA_SIZE_64*/

unsigned char *xxtea_encrypt(const unsigned char *text,
			     xxtea_length_t srclen,
			     const unsigned char *key,
			     xxtea_length_t keylen,
			     xxtea_length_t *dstlen);

unsigned char *xxtea_decrypt(const unsigned char *encrypt_data,
			     xxtea_length_t enlen,
			     const unsigned char *key,
			     xxtea_length_t keylen,
			     xxtea_length_t *srclen);

const unsigned char *xxtea_getsource(const unsigned char *decrypt_data,
				     xxtea_length_t ret_length);

void xxtea_release(unsigned char *data);

#ifdef __cplusplus
}
#endif

#endif /*__XXTEA_H__*/
