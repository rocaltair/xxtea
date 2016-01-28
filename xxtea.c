#include "xxtea.h"
#define DELTA 0x9e3779b9
#define MX(e, y, z, k, p, sum) (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (k[(p&3)^e] ^ z)))
#define ALIGN(n, a) (((n) & (a-1)) == 0) ? (n) : ((n) + a - ((n) & (a-1)))

#define DEFAULT_BUFF_ARRAY_SIZE 256 * 1024 /*256 KB*/
static unsigned char default_buff_array[DEFAULT_BUFF_ARRAY_SIZE];

static void *myalloc(size_t size)
{
	if (size <= DEFAULT_BUFF_ARRAY_SIZE)
		return &default_buff_array;
	return malloc(size);
}

static void myfree(void *ptr)
{
	if (ptr == &default_buff_array)
		return;
	free(ptr);
}

static void btea(uint32_t *v, int n, uint32_t const k[4])
{
	uint32_t y, z, sum;
	unsigned p, rounds, e;
	if (n > 1) {          /* Coding Part */
		rounds = 8 + 52/n;
		sum = 0;
		z = v[n-1];
		do {
			sum += DELTA;
			e = (sum >> 2) & 3;
			for (p=0; p<n-1; p++) {
				y = v[p+1]; 
				z = v[p] += MX(e, y, z, k, p, sum);
			}
			y = v[0];
			z = v[n-1] += MX(e, y, z, k, p, sum);
		} while (--rounds);
	} else if (n < -1) {  /* Decoding Part */
		n = -n;
		rounds = 8 + 52/n;
		sum = rounds*DELTA;
		y = v[0];
		do {
			e = (sum >> 2) & 3;
			for (p=n-1; p>0; p--) {
				z = v[p-1];
				y = v[p] -= MX(e, y, z, k, p, sum);
			}
			z = v[n-1];
			y = v[0] -= MX(e, y, z, k, p, sum);
		} while ((sum -= DELTA) != 0);
	}
}

static void getkey(const unsigned char *key, xxtea_length_t key_length, uint32_t *k)
{
	unsigned char buf[5];
	unsigned char realkey[17] = {0};
	xxtea_length_t i,j;
	memcpy(realkey, key, key_length < sizeof(realkey)-1 ? key_length : sizeof(realkey)-1);
	buf[4] = 0;
	for( i=0,j=0; j<4; i+=4,j++ ){
		buf[0] = realkey[i];
		buf[1] = realkey[i+1];
		buf[2] = realkey[i+2];
		buf[3] = realkey[i+3];
		k[j] = strtoul((const char *)buf, NULL, 16 );
	}
}

unsigned char *xxtea_encrypt(const unsigned char *text,
			     xxtea_length_t srclen,
			     const unsigned char *key,
			     xxtea_length_t keylen,
			     xxtea_length_t *dstlen)
{
	uint32_t k[4];
	unsigned char *buf;
	xxtea_length_t l;

	getkey(key, keylen, k);

	l = ALIGN(srclen + sizeof(srclen), 4);
	buf = (unsigned char *)myalloc( l );
	memcpy(buf, (unsigned char *)&srclen, sizeof(srclen));
	memcpy(&buf[sizeof(srclen)], text, srclen);

	btea( (uint32_t *)(buf+sizeof(srclen)), (l-sizeof(srclen))/sizeof(uint32_t), k );
	*dstlen = l;
	return buf;
}

unsigned char *xxtea_decrypt(const unsigned char *encrypt_data,
			     xxtea_length_t enlen,
			     const unsigned char *key,
			     xxtea_length_t keylen,
			     xxtea_length_t *srclen)
{
	uint32_t k[4];
	unsigned char *buf;
	xxtea_length_t ret_length;
	xxtea_length_t l;

	getkey(key, keylen, k);
	l = ALIGN(enlen, 4);
	buf = myalloc( l );
	memcpy( buf, encrypt_data, enlen );

	btea( (uint32_t *)(buf+sizeof(ret_length)), -((enlen-sizeof(ret_length))/sizeof(uint32_t)), k );

	memcpy( (unsigned char *)&ret_length, buf, sizeof(ret_length) );
	if( ret_length > (l - sizeof(ret_length)) )  ret_length = l - sizeof(ret_length);
	*srclen = ret_length;
	return buf;
}

const unsigned char *xxtea_getsource(const unsigned char *decrypt_data,
				     xxtea_length_t ret_length)
{
	return &decrypt_data[sizeof(ret_length)];
}

void xxtea_release(unsigned char *dst)
{
	myfree((void *)dst);
}

#ifdef ENABLE_LUA_XXTEA
/*	
	This is libray of http://en.wikipedia.org/wiki/XXTEA for lua for very simple encryption.
	compile in gcc with
	gcc --shared -fPIC -O2 -o xxtea.so xxtea.c
	use in lua
	require'xxtea'
	str = 'something'
	encstr = xxtea.encrypt( str, 'abcd1234abcd1234' )
	decstr = xxtea.decrypt( encstr, 'abcd1234abcd1234' )
	where the key is a 128 bit hex string
*/

static int lua__encrypt( lua_State *L )
{
	size_t text_length;
	size_t key_length;
	xxtea_length_t ret_length;
	const unsigned char *text = (const unsigned char *)luaL_checklstring( L, 1, &text_length );
	const unsigned char *key = (const unsigned char *)luaL_checklstring( L, 2, &key_length );
	unsigned char *es = xxtea_encrypt(text, (xxtea_length_t)text_length, key, (xxtea_length_t)key_length, &ret_length);
	lua_pushlstring(L, (const char *)es, ret_length);
	xxtea_release(es);
	return 1;
}


static int lua__decrypt( lua_State *L ){
	size_t en_length;
	size_t key_length;
	xxtea_length_t ret_length;
	const unsigned char *encrypt_data = (const unsigned char *)luaL_checklstring( L, 1, &en_length );
	const unsigned char *key = (const unsigned char *)luaL_checklstring( L, 2, &key_length );
	unsigned char *decrypt_data = xxtea_decrypt(encrypt_data, (xxtea_length_t)en_length, key, (xxtea_length_t)key_length, &ret_length);
	lua_pushlstring(L, (const char *)xxtea_getsource(decrypt_data, ret_length), ret_length);
	xxtea_release(decrypt_data);
	return 1;
}

/* register library */
LUALIB_API int luaopen_xxtea( lua_State *L )
{
	static const struct luaL_reg xxtea [] = {
		{"encrypt", lua__encrypt},
		{"decrypt", lua__decrypt},
		{NULL, NULL}
	};
	luaL_openlib(L, "xxtea", xxtea, 0);
	return 1;
}
#endif /*ENABLE_LUA_XXTEA*/


#ifdef ENABLE_XXTEA_MAIN

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <math.h>

#define XXTEA_PREFIX ".xxt"
#define XXTEA_PREFIX_LEN 4

#define XXTEA_KEY_LEN 16
#define XXTEA_KEY_A (int)(M_LN10 * 123456789)
#define XXTEA_KEY_B (int)(M_SQRT2 * 123456789)
#define XXTEA_KEY_SET(buff, a, b) \
        (unsigned char *) (!buff[0] ? (sprintf((char *)&buff, "%08X%08X", ((int)(M_E) * a) ^ b, ((int)(M_PI) *b) ^ a), &buff) : &buff)


#define DEFAULT_BUFF_SIZE  1 * 1024 * 1024 /*1 MB*/
#define BUFF_APPEND_SIZE 8 * 1024 /* 8 KB*/
const char *USAGE = ""
        "-d : use decrpt mode\n"
        "-p : prefix\n"
        "-k : key\n"
        "-i : input filepath, stdin default\n"
        "-o : output filepath, stdout default\n";

const char *infile = NULL;
const char *outfile = NULL;
const char *key = NULL;
const char *prefix = NULL;
int decrypto_flag = 0;

static unsigned char default_key[XXTEA_KEY_LEN + 1] = {0};


void parse_flag(int argc, char **argv)
{
        char opt;
        while ((opt = getopt(argc, argv, "dp:i:o:k:")) != -1) {
                switch (opt) {
                        case 'p':
                                prefix = optarg;
                                break;
                        case 'd':
                                decrypto_flag = 1;
                                break;
                        case 'i':
                                infile = optarg;
                                break;
                        case 'o':
                                outfile = optarg;
                                break;
                        case 'k':
                                key = optarg;
                                break;
                        default: /* '?' */
                                fprintf(stderr, "Usage: %s [-d] [-p prefix] -k [key] [-i input] [-o output]\n",
                                                argv[0]);
                                fprintf(stderr, "%s", USAGE);
                                exit(EXIT_FAILURE);
                }
        }
}

int main(int argc, char **argv)
{
        size_t read_size = 0;
        size_t buff_size = DEFAULT_BUFF_SIZE;
        size_t left_size = buff_size - read_size;
        unsigned char *buff = (unsigned char *)malloc(sizeof(unsigned char) * buff_size);
        parse_flag(argc, argv);
        if (key == NULL) {
                /*key = 2B8B215B0FC9D64A*/
                key = (const char *)XXTEA_KEY_SET(default_key, XXTEA_KEY_A, XXTEA_KEY_B);
        }
        if (infile != NULL) {
                freopen(infile, "r", stdin);
        }
        if (outfile != NULL) {
                freopen(outfile, "w", stdout);
        }

        do {
                left_size = buff_size - read_size;
                read_size += fread((void *)&buff[read_size], sizeof(unsigned char), buff_size - read_size, stdin);
                if (feof(stdin)) {
                        break;
                }
                if (buff_size - read_size < BUFF_APPEND_SIZE) {
                        unsigned char *new_buff = realloc(buff, buff_size + DEFAULT_BUFF_SIZE);
                        if (new_buff == NULL) {
                                free(buff);
                                fprintf(stderr, "realloc failed!\n");
                                exit(EXIT_FAILURE);
                        }
                        buff = new_buff;
                        buff_size += DEFAULT_BUFF_SIZE;
                }
        } while (1);
        xxtea_length_t ret_length;
        size_t write_size = 0;
        if (decrypto_flag) {
                if (prefix != NULL && strstr((const char *)buff, prefix) != (char *)buff) {
                        fprintf(stderr, "prefix=%s did not match!\n", prefix);
                        exit(EXIT_FAILURE);
                }
                size_t prefix_size = prefix == NULL ? 0 : strlen(prefix);
                unsigned char *decrypt_data = xxtea_decrypt(buff+prefix_size, read_size-prefix_size, (unsigned char *)key, (xxtea_length_t)strlen(key), &ret_length);
                const unsigned char *text = xxtea_getsource(decrypt_data, ret_length);
                while ( (write_size += fwrite(
                                (void *)&text[write_size], 
                                sizeof(unsigned char), 
                                ret_length - write_size, 
                                stdout)
                        ) < ret_length ) {
                }
                xxtea_release(decrypt_data);
        } else {
                if (prefix != NULL) {
                        fwrite((void *)prefix, sizeof(unsigned char), strlen(prefix), stdout);
                }
                unsigned char *out = xxtea_encrypt(buff, read_size, (unsigned char *)key, (xxtea_length_t)strlen(key), &ret_length);
                while ( (write_size += fwrite(
                                (void *)&out[write_size], 
                                sizeof(unsigned char), 
                                ret_length - write_size, 
                                stdout)
                        ) < ret_length ) {
                }
                xxtea_release(out);
        }
        free(buff);
        return 0;
}

#endif //ENABLE_XXTEA_MAIN
