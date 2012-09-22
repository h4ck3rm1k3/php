/*
   +----------------------------------------------------------------------+
   | PHP Version 5                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2012 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Stig Bakken <ssb@php.net>                                   |
   |          Zeev Suraski <zeev@zend.com>                                |
   |          Rasmus Lerdorf <rasmus@php.net>                             |
   |          Pierre Joye <pierre@php.net>                                |
   +----------------------------------------------------------------------+
*/

/* $Id$ */

#include <stdlib.h>

#include "php.h"
#if HAVE_CRYPT

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if PHP_USE_PHP_CRYPT_R
# include "php_crypt_r.h"
# include "crypt_freesec.h"
#endif
#if HAVE_CRYPT_H
# if defined(CRYPT_R_GNU_SOURCE) && !defined(_GNU_SOURCE)
#  define _GNU_SOURCE
# endif
# include <crypt.h>
#endif
#if TM_IN_SYS_TIME
#include <sys/time.h>
#else
#include <time.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#ifdef PHP_WIN32
#include <process.h>
#endif

#include "php_lcg.h"
#include "php_crypt.h"
#include "php_rand.h"

/* The capabilities of the crypt() function is determined by the test programs
 * run by configure from aclocal.m4.  They will set PHP_STD_DES_CRYPT,
 * PHP_EXT_DES_CRYPT, PHP_MD5_CRYPT and PHP_BLOWFISH_CRYPT as appropriate
 * for the target platform. */

#if defined(HAVE_CRYPT_R) && (defined(_REENTRANT) || defined(_THREAD_SAFE))
# define PHP_USE_SYSTEM_CRYPT_R
#endif

#define PHP_MAX_STD_DES_SALT_LEN 2
#define PHP_MAX_STD_DES_HASH_LEN 11

#define PHP_MAX_EXT_DES_SALT_LEN 9
#define PHP_MAX_EXT_DES_HASH_LEN 11

#define PHP_MAX_MD5_SALT_LEN 12
#define PHP_MAX_MD5_HASH_LEN 22

#define PHP_MAX_BLOWFISH_SALT_LEN 29
#define PHP_MAX_BLOWFISH_HASH_LEN 31
 
#define PHP_MAX_SHA256_SALT_LEN 37
#define PHP_MAX_SHA256_HASH_LEN 43

#define PHP_MAX_SHA512_SALT_LEN 37
#define PHP_MAX_SHA512_HASH_LEN 86

/* 
 * Maximum salt length is from SHA512
 * Maximum hash length is from SHA512
 */
#define PHP_MAX_SALT_LEN 37
#define PHP_MAX_HASH_LEN 86

#define PHP_CRYPT_RAND php_rand(TSRMLS_C)

PHP_MINIT_FUNCTION(crypt) /* {{{ */
{
	REGISTER_LONG_CONSTANT("CRYPT_SALT_LENGTH", PHP_MAX_SALT_LEN, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("CRYPT_STD_DES", PHP_STD_DES_CRYPT | PHP_USE_PHP_CRYPT_R, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("CRYPT_EXT_DES", PHP_EXT_DES_CRYPT | PHP_USE_PHP_CRYPT_R, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("CRYPT_MD5", PHP_MD5_CRYPT | PHP_USE_PHP_CRYPT_R, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("CRYPT_BLOWFISH", PHP_BLOWFISH_CRYPT | PHP_USE_PHP_CRYPT_R, CONST_CS | CONST_PERSISTENT);
#ifdef PHP_SHA256_CRYPT
	REGISTER_LONG_CONSTANT("CRYPT_SHA256", PHP_SHA256_CRYPT | PHP_USE_PHP_CRYPT_R, CONST_CS | CONST_PERSISTENT);
#endif

#ifdef PHP_SHA512_CRYPT
	REGISTER_LONG_CONSTANT("CRYPT_SHA512", PHP_SHA512_CRYPT | PHP_USE_PHP_CRYPT_R, CONST_CS | CONST_PERSISTENT);
#endif

#if PHP_USE_PHP_CRYPT_R
	php_init_crypt_r();
#endif

	return SUCCESS;
}
/* }}} */

#if PHP_USE_PHP_CRYPT_R
PHP_MSHUTDOWN_FUNCTION(crypt) /* {{{ */
{
	php_shutdown_crypt_r();

	return SUCCESS;
}
/* }}} */
#endif

static unsigned char itoa64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void php_to64(char *s, long v, int n) /* {{{ */
{
	while (--n >= 0) {
		*s++ = itoa64[v&0x3f];
		v >>= 6;
	}
}
/* }}} */

/* {{{ proto string crypt(string str [, string salt])
   Hash a string */
PHP_FUNCTION(crypt)
{
	char salt[PHP_MAX_SALT_LEN + 1];
	int salt_len = 0;
	char output[PHP_MAX_SALT_LEN + PHP_MAX_HASH_LEN + 1];
	char *str, *salt_in = NULL;
	int str_len, salt_in_len = 0;
	char *crypt_res = NULL;
#if PHP_USE_PHP_CRYPT_R
	struct php_crypt_extended_data extended_buffer;
#endif
#if defined(PHP_USE_SYSTEM_CRYPT_R)
#  if defined(CRYPT_R_STRUCT_CRYPT_DATA)
	struct crypt_data buffer;
#  elif defined(CRYPT_R_CRYPTD)
	CRYPTD buffer;
#  else
#    error Data struct used by crypt_r() is unknown. Please report.
#  endif
#endif

	salt[0] = salt[PHP_MAX_SALT_LEN] = '\0';

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &str, &str_len, &salt_in, &salt_in_len) == FAILURE) {
		return;
	}

	if (salt_in && (salt_in_len > 0)) {
		salt_len = MIN(PHP_MAX_SALT_LEN, salt_in_len);
		memcpy(salt, salt_in, salt_len);
		salt[salt_len] = '\0';
	} else {
		/* Use SHA512 as default algorithm */
		salt[0] = '$'; salt[1] = '6'; salt[2] = '$';
		php_to64(&salt[3],  PHP_CRYPT_RAND, 4);
		php_to64(&salt[7],  PHP_CRYPT_RAND, 4);
		php_to64(&salt[11], PHP_CRYPT_RAND, 4);
		salt[15] = '$'; salt[16] = '\0';
		salt_len = 16;
	}

	{
#if PHP_USE_PHP_CRYPT_R
		memset(&extended_buffer, 0, sizeof(extended_buffer));
#endif
#if defined(PHP_USE_SYSTEM_CRYPT_R)
# if defined(CRYPT_R_STRUCT_CRYPT_DATA)
		buffer->initialized = 0;
# else
		memset(&buffer, 0, sizeof(buffer));
# endif
#endif

		if (salt[0]=='$' && salt[1]=='1' && salt[2]=='$') {
			/* CRYPT_MD5 */
#if PHP_MD5_CRYPT
# if defined(PHP_USE_SYSTEM_CRYPT_R)
# warning Using system MD5 crypt function, which is OK on Debian system
			crypt_res = crypt_r(str, salt, &buffer);
# else
			crypt_res = crypt(str, salt);
# endif
#elif PHP_USE_PHP_CRYPT_R
# error Using PHP MD5 crypt function, should not happen on Debian system
			crypt_res = php_md5_crypt_r(str, salt, output);
#endif
		} else if (salt[0]=='$' && salt[1]=='6' && salt[2]=='$') {
			/* CRYPT_SHA512 */
#if PHP_SHA512_CRYPT
# warning Using system SHA512 crypt function, which is OK on Debian system
# if defined(PHP_USE_SYSTEM_CRYPT_R)
			crypt_res = crypt_r(str, salt, &buffer);
# else
			crypt_res = crypt(str, salt);
# endif
#elif PHP_USE_PHP_CRYPT_R
# error Using PHP SHA512 crypt function, should not happen on Debian system
			crypt_res = php_sha512_crypt_r(str, salt, output, sizeof(output));
#endif
		} else if (salt[0]=='$' && salt[1]=='5' && salt[2]=='$') {
			/* CRYPT_SHA256 */
#if PHP_SHA256_CRYPT
# warning Using system SHA256 crypt function, which is OK on Debian system
# if defined(PHP_USE_SYSTEM_CRYPT_R)
			crypt_res = crypt_r(str, salt, &buffer);
# else
			crypt_res = crypt(str, salt);
# endif
#elif PHP_USE_PHP_CRYPT_R
# error Using PHP SHA256 crypt function, should not happen on Debian system
			crypt_res = php_sha256_crypt_r(str, salt, output, sizeof(output));
#endif
		} else if (
				salt[0] == '$' &&
				salt[1] == '2' &&
				salt[2] >= 'a' && salt[2] <= 'z' &&
				salt[3] == '$' &&
				salt[6] == '$') {
			/* CRYPT_BLOWFISH */
#if PHP_BLOWFISH_CRYPT
# error Using system BlowFish crypt function, should not happen on Debian system
# if defined(PHP_USE_SYSTEM_CRYPT_R)
			crypt_res = crypt_r(str, salt, &buffer);
# else
			crypt_res = crypt(str, salt);
# endif
#elif PHP_USE_PHP_CRYPT_R
# warning Using PHP BlowFish crypt function, which is OK on Debian system
			crypt_res = php_crypt_blowfish_rn(str, salt, output, sizeof(output));
#endif
		} else if (salt[0]=='_' && 
				   salt_len == 9) {
			/* CRYPT_EXT_DES */
#if PHP_EXT_DES_CRYPT
# error Using system extended DES crypt function, should not happen on Debian system
# if defined(PHP_USE_SYSTEM_CRYPT_R)
			crypt_res = crypt_r(str, salt, &buffer);
# else
			crypt_res = crypt(str, salt);
# endif
#elif PHP_USE_PHP_CRYPT_R
# warning Using PHP extended DES crypt function, which is OK on Debian system
			_crypt_extended_init_r();
			crypt_res = _crypt_extended_r(str, salt, &extended_buffer);
#endif
		} else {
			/* CRYPT_STD_DES */
#if PHP_STD_DES_CRYPT
# warning Using system standard DES crypt function, which is OK on Debian system
# if defined(PHP_USE_SYSTEM_CRYPT_R)
			crypt_res = crypt_r(str, salt, &buffer);
# else
			crypt_res = crypt(str, salt);
# endif
#elif PHP_USE_PHP_CRYPT_R
# error Using PHP standard DES crypt function, should not happen on Debian system
			_crypt_extended_init_r();
			crypt_res = _crypt_extended_r(str, salt, &extended_buffer);
#endif
		}

		if (!crypt_res) {
			if (salt[0]=='*' && salt[1]=='0') {
				RETVAL_STRING("*1", 1);
			} else {
				RETVAL_STRING("*0", 1);
			}
		} else {
			RETVAL_STRING(crypt_res, 1);
		}
		memset(salt, 0, sizeof(salt));
		if (output[0]!='\0') {
			memset(output, 0, sizeof(output));
		}
	}
}
/* }}} */
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
