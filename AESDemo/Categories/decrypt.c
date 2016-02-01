#include "decrypt.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>


/*
 **********************************************************************
 ** md5.h -- Header file for implementation of MD5                   **
 ** RSA Data Security, Inc. MD5 Message Digest Algorithm             **
 ** Created: 2/17/90 RLR                                             **
 ** Revised: 12/27/90 SRD,AJ,BSK,JT Reference C version              **
 ** Revised (for MD5): RLR 4/27/91                                   **
 **   -- G modified to have y&~z instead of y&z                      **
 **   -- FF, GG, HH modified to add in last register done            **
 **   -- Access pattern: round 2 works mod 5, round 3 works mod 3    **
 **   -- distinct additive constant for each step                    **
 **   -- round 4 added, working mod 7                                **
 **********************************************************************
 */

/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** License to copy and use this software is granted provided that   **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     **
 ** Digest Algorithm" in all material mentioning or referencing this **
 ** software or this function.                                       **
 **                                                                  **
 ** License is also granted to make and use derivative works         **
 ** provided that such works are identified as "derived from the RSA **
 ** Data Security, Inc. MD5 Message Digest Algorithm" in all         **
 ** material mentioning or referencing the derived work.             **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.             **
 **                                                                  **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

/* typedef a 32 bit type */
typedef uint32_t UINT4;

/* Data structure for MD5 (Message Digest) computation */
typedef struct {
    UINT4 i[2];                   /* number of _bits_ handled mod 2^64 */
    UINT4 buf[4];                                    /* scratch buffer */
    unsigned char in[64];                              /* input buffer */
    unsigned char digest[16];     /* actual digest after MD5Final call */
} MD5_CTX;

void MD5Init ();
void MD5Update ();
void MD5Final ();

/*
 **********************************************************************
 ** End of md5.h                                                     **
 ******************************* (cut) ********************************
 */

/*
 **********************************************************************
 ** md5.c                                                            **
 ** RSA Data Security, Inc. MD5 Message Digest Algorithm             **
 ** Created: 2/17/90 RLR                                             **
 ** Revised: 1/91 SRD,AJ,BSK,JT Reference C Version                  **
 **********************************************************************
 */

/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** License to copy and use this software is granted provided that   **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     **
 ** Digest Algorithm" in all material mentioning or referencing this **
 ** software or this function.                                       **
 **                                                                  **
 ** License is also granted to make and use derivative works         **
 ** provided that such works are identified as "derived from the RSA **
 ** Data Security, Inc. MD5 Message Digest Algorithm" in all         **
 ** material mentioning or referencing the derived work.             **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.             **
 **                                                                  **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

/* -- include the following line if the md5.h header file is separate -- */
/* #include "md5.h" */

/* forward declaration */
static void Transform ();

static unsigned char PADDING[64] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* F, G and H are basic MD5 functions: selection, majority, parity */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
{(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
(a) = ROTATE_LEFT ((a), (s)); \
(a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) \
{(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
(a) = ROTATE_LEFT ((a), (s)); \
(a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) \
{(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
(a) = ROTATE_LEFT ((a), (s)); \
(a) += (b); \
}
#define II(a, b, c, d, x, s, ac) \
{(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
(a) = ROTATE_LEFT ((a), (s)); \
(a) += (b); \
}

void MD5Init (mdContext)
MD5_CTX *mdContext;
{
    mdContext->i[0] = mdContext->i[1] = (UINT4)0;
    
    /* Load magic initialization constants.
     */
    mdContext->buf[0] = (UINT4)0x67452301;
    mdContext->buf[1] = (UINT4)0xefcdab89;
    mdContext->buf[2] = (UINT4)0x98badcfe;
    mdContext->buf[3] = (UINT4)0x10325476;
}

void MD5Update (mdContext, inBuf, inLen)
MD5_CTX *mdContext;
unsigned char *inBuf;
unsigned int inLen;
{
    UINT4 in[16];
    int32_t mdi;
    uint32_t i, ii;
    
    /* compute number of bytes mod 64 */
    mdi = (int32_t)((mdContext->i[0] >> 3) & 0x3F);
    
    /* update number of bits */
    if ((mdContext->i[0] + ((UINT4)inLen << 3)) < mdContext->i[0])
        mdContext->i[1]++;
    mdContext->i[0] += ((UINT4)inLen << 3);
    mdContext->i[1] += ((UINT4)inLen >> 29);
    
    while (inLen--) {
        /* add new character to buffer, increment mdi */
        mdContext->in[mdi++] = *inBuf++;
        
        /* transform if necessary */
        if (mdi == 0x40) {
            for (i = 0, ii = 0; i < 16; i++, ii += 4)
                in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
                (((UINT4)mdContext->in[ii+2]) << 16) |
                (((UINT4)mdContext->in[ii+1]) << 8) |
                ((UINT4)mdContext->in[ii]);
            Transform (mdContext->buf, in);
            mdi = 0;
        }
    }
}

void MD5Final (mdContext)
MD5_CTX *mdContext;
{
    UINT4 in[16];
    int32_t mdi;
    uint32_t i, ii;
    uint32_t padLen;
    
    /* save number of bits */
    in[14] = mdContext->i[0];
    in[15] = mdContext->i[1];
    
    /* compute number of bytes mod 64 */
    mdi = (int32_t)((mdContext->i[0] >> 3) & 0x3F);
    
    /* pad out to 56 mod 64 */
    padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
    MD5Update (mdContext, PADDING, padLen);
    
    /* append length in bits and transform */
    for (i = 0, ii = 0; i < 14; i++, ii += 4)
        in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
        (((UINT4)mdContext->in[ii+2]) << 16) |
        (((UINT4)mdContext->in[ii+1]) << 8) |
        ((UINT4)mdContext->in[ii]);
        Transform (mdContext->buf, in);
        
    /* store buffer in digest */
        for (i = 0, ii = 0; i < 4; i++, ii += 4) {
            mdContext->digest[ii] = (unsigned char)(mdContext->buf[i] & 0xFF);
            mdContext->digest[ii+1] =
            (unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
            mdContext->digest[ii+2] =
            (unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
            mdContext->digest[ii+3] =
            (unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
        }
}

/* Basic MD5 step. Transform buf based on in.
 */
static void Transform (buf, in)
UINT4 *buf;
UINT4 *in;
{
    UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];
    
    /* Round 1 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
    FF ( a, b, c, d, in[ 0], S11, 3614090360); /* 1 */
    FF ( d, a, b, c, in[ 1], S12, 3905402710); /* 2 */
    FF ( c, d, a, b, in[ 2], S13,  606105819); /* 3 */
    FF ( b, c, d, a, in[ 3], S14, 3250441966); /* 4 */
    FF ( a, b, c, d, in[ 4], S11, 4118548399); /* 5 */
    FF ( d, a, b, c, in[ 5], S12, 1200080426); /* 6 */
    FF ( c, d, a, b, in[ 6], S13, 2821735955); /* 7 */
    FF ( b, c, d, a, in[ 7], S14, 4249261313); /* 8 */
    FF ( a, b, c, d, in[ 8], S11, 1770035416); /* 9 */
    FF ( d, a, b, c, in[ 9], S12, 2336552879); /* 10 */
    FF ( c, d, a, b, in[10], S13, 4294925233); /* 11 */
    FF ( b, c, d, a, in[11], S14, 2304563134); /* 12 */
    FF ( a, b, c, d, in[12], S11, 1804603682); /* 13 */
    FF ( d, a, b, c, in[13], S12, 4254626195); /* 14 */
    FF ( c, d, a, b, in[14], S13, 2792965006); /* 15 */
    FF ( b, c, d, a, in[15], S14, 1236535329); /* 16 */
    
    /* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20
    GG ( a, b, c, d, in[ 1], S21, 4129170786); /* 17 */
    GG ( d, a, b, c, in[ 6], S22, 3225465664); /* 18 */
    GG ( c, d, a, b, in[11], S23,  643717713); /* 19 */
    GG ( b, c, d, a, in[ 0], S24, 3921069994); /* 20 */
    GG ( a, b, c, d, in[ 5], S21, 3593408605); /* 21 */
    GG ( d, a, b, c, in[10], S22,   38016083); /* 22 */
    GG ( c, d, a, b, in[15], S23, 3634488961); /* 23 */
    GG ( b, c, d, a, in[ 4], S24, 3889429448); /* 24 */
    GG ( a, b, c, d, in[ 9], S21,  568446438); /* 25 */
    GG ( d, a, b, c, in[14], S22, 3275163606); /* 26 */
    GG ( c, d, a, b, in[ 3], S23, 4107603335); /* 27 */
    GG ( b, c, d, a, in[ 8], S24, 1163531501); /* 28 */
    GG ( a, b, c, d, in[13], S21, 2850285829); /* 29 */
    GG ( d, a, b, c, in[ 2], S22, 4243563512); /* 30 */
    GG ( c, d, a, b, in[ 7], S23, 1735328473); /* 31 */
    GG ( b, c, d, a, in[12], S24, 2368359562); /* 32 */
    
    /* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23
    HH ( a, b, c, d, in[ 5], S31, 4294588738); /* 33 */
    HH ( d, a, b, c, in[ 8], S32, 2272392833); /* 34 */
    HH ( c, d, a, b, in[11], S33, 1839030562); /* 35 */
    HH ( b, c, d, a, in[14], S34, 4259657740); /* 36 */
    HH ( a, b, c, d, in[ 1], S31, 2763975236); /* 37 */
    HH ( d, a, b, c, in[ 4], S32, 1272893353); /* 38 */
    HH ( c, d, a, b, in[ 7], S33, 4139469664); /* 39 */
    HH ( b, c, d, a, in[10], S34, 3200236656); /* 40 */
    HH ( a, b, c, d, in[13], S31,  681279174); /* 41 */
    HH ( d, a, b, c, in[ 0], S32, 3936430074); /* 42 */
    HH ( c, d, a, b, in[ 3], S33, 3572445317); /* 43 */
    HH ( b, c, d, a, in[ 6], S34,   76029189); /* 44 */
    HH ( a, b, c, d, in[ 9], S31, 3654602809); /* 45 */
    HH ( d, a, b, c, in[12], S32, 3873151461); /* 46 */
    HH ( c, d, a, b, in[15], S33,  530742520); /* 47 */
    HH ( b, c, d, a, in[ 2], S34, 3299628645); /* 48 */
    
    /* Round 4 */
#define S41 6
#define S42 10
#define S43 15
#define S44 21
    II ( a, b, c, d, in[ 0], S41, 4096336452); /* 49 */
    II ( d, a, b, c, in[ 7], S42, 1126891415); /* 50 */
    II ( c, d, a, b, in[14], S43, 2878612391); /* 51 */
    II ( b, c, d, a, in[ 5], S44, 4237533241); /* 52 */
    II ( a, b, c, d, in[12], S41, 1700485571); /* 53 */
    II ( d, a, b, c, in[ 3], S42, 2399980690); /* 54 */
    II ( c, d, a, b, in[10], S43, 4293915773); /* 55 */
    II ( b, c, d, a, in[ 1], S44, 2240044497); /* 56 */
    II ( a, b, c, d, in[ 8], S41, 1873313359); /* 57 */
    II ( d, a, b, c, in[15], S42, 4264355552); /* 58 */
    II ( c, d, a, b, in[ 6], S43, 2734768916); /* 59 */
    II ( b, c, d, a, in[13], S44, 1309151649); /* 60 */
    II ( a, b, c, d, in[ 4], S41, 4149444226); /* 61 */
    II ( d, a, b, c, in[11], S42, 3174756917); /* 62 */
    II ( c, d, a, b, in[ 2], S43,  718787259); /* 63 */
    II ( b, c, d, a, in[ 9], S44, 3951481745); /* 64 */
    
    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}

/*
 **********************************************************************
 ** End of md5.c                                                     **
 ******************************* (cut) ********************************
 */

/*
 **********************************************************************
 ** md5driver.c -- sample routines to test                           **
 ** RSA Data Security, Inc. MD5 message digest algorithm.            **
 ** Created: 2/16/90 RLR                                             **
 ** Updated: 1/91 SRD                                                **
 **********************************************************************
 */

/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.             **
 **                                                                  **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

/* -- include the following file if the file md5.h is separate -- */
/* #include "md5.h" */

/* Prints message digest buffer in mdContext as 32 hexadecimal digits.
 Order is from low-order byte to high-order byte of digest.
 Each byte is printed with high-order hexadecimal digit first.
 */
static void MDPrint (mdContext)
MD5_CTX *mdContext;
{
    int i;
    
    for (i = 0; i < 16; i++)
        printf ("%02x", mdContext->digest[i]);
        }

/* size of test block */
#define TEST_BLOCK_SIZE 1000

/* number of blocks to process */
#define TEST_BLOCKS 10000

/* number of test bytes = TEST_BLOCK_SIZE * TEST_BLOCKS */
static long TEST_BYTES = (long)TEST_BLOCK_SIZE * (long)TEST_BLOCKS;

/* A time trial routine, to measure the speed of MD5.
 Measures wall time required to digest TEST_BLOCKS * TEST_BLOCK_SIZE
 characters.
 */
static void MDTimeTrial ()
{
    MD5_CTX mdContext;
    time_t endTime, startTime;
    unsigned char data[TEST_BLOCK_SIZE];
    uint32_t i;
    
    /* initialize test data */
    for (i = 0; i < TEST_BLOCK_SIZE; i++)
        data[i] = (unsigned char)(i & 0xFF);
    
    /* start timer */
    printf ("MD5 time trial. Processing %ld characters...\n", TEST_BYTES);
    time (&startTime);
    
    /* digest data in TEST_BLOCK_SIZE byte blocks */
    MD5Init (&mdContext);
    for (i = TEST_BLOCKS; i > 0; i--)
        MD5Update (&mdContext, data, TEST_BLOCK_SIZE);
    MD5Final (&mdContext);
    
    /* stop timer, get time difference */
    time (&endTime);
    MDPrint (&mdContext);
    printf (" is digest of test input.\n");
    printf
    ("Seconds to process test input: %ld\n", (long)(endTime-startTime));
    printf
    ("Characters processed per second: %ld\n",
     TEST_BYTES/(endTime-startTime));
}

/* Computes the message digest for string inString.
 Prints out message digest, a space, the string (in quotes) and a
 carriage return.
 */
static void MDString (inString)
char *inString;
{
    MD5_CTX mdContext;
    uint32_t len = strlen (inString);
    
    MD5Init (&mdContext);
    MD5Update (&mdContext, inString, len);
    MD5Final (&mdContext);
    MDPrint (&mdContext);
    printf (" \"%s\"\n\n", inString);
}

/* Computes the message digest for a specified file.
 Prints out message digest, a space, the file name, and a carriage
 return.
 */
static void MDFile (filename)
char *filename;
{
    FILE *inFile = fopen (filename, "rb");
    MD5_CTX mdContext;
    int32_t bytes;
    unsigned char data[1024];
    
    if (inFile == NULL) {
        printf ("%s can't be opened.\n", filename);
        return;
    }
    
    MD5Init (&mdContext);
    while ((bytes = fread (data, 1, 1024, inFile)) != 0)
        MD5Update (&mdContext, data, bytes);
        MD5Final (&mdContext);
        MDPrint (&mdContext);
        printf (" %s\n", filename);
        fclose (inFile);
        }

/* Writes the message digest of the data from stdin onto stdout,
 followed by a carriage return.
 */
static void MDFilter ()
{
    MD5_CTX mdContext;
    int32_t bytes;
    unsigned char data[16];
    
    MD5Init (&mdContext);
    while ((bytes = fread (data, 1, 16, stdin)) != 0)
        MD5Update (&mdContext, data, bytes);
    MD5Final (&mdContext);
    MDPrint (&mdContext);
    printf ("\n");
}

/* Runs a standard suite of test data.
 */
 void MDTestSuite ()
{
    printf ("MD5 test suite results:\n\n");
    MDString ("");
    MDString ("a");
    MDString ("abc");
    MDString ("message digest");
    MDString ("abcdefghijklmnopqrstuvwxyz");
    MDString
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    MDString
    ("1234567890123456789012345678901234567890\
     1234567890123456789012345678901234567890");
    /* Contents of file foo are "abc" */
    MDFile ("foo");
}









#ifdef __BIG_ENDIAN__
# define SHA_BIG_ENDIAN
#elif defined __LITTLE_ENDIAN__
/* override */
#elif defined __BYTE_ORDER
# if __BYTE_ORDER__ ==  __ORDER_BIG_ENDIAN__
# define SHA_BIG_ENDIAN
# endif
#else // ! defined __LITTLE_ENDIAN__
# include <endian.h> // machine/endian.h
# if __BYTE_ORDER__ ==  __ORDER_BIG_ENDIAN__
#  define SHA_BIG_ENDIAN
# endif
#endif


/* header */

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

typedef struct sha1nfo {
    uint32_t buffer[BLOCK_LENGTH/4];
    uint32_t state[HASH_LENGTH/4];
    uint32_t byteCount;
    uint8_t bufferOffset;
    uint8_t keyBuffer[BLOCK_LENGTH];
    uint8_t innerHash[HASH_LENGTH];
} sha1nfo;

/* public API - prototypes - TODO: doxygen*/

/**
 */
void sha1_init(sha1nfo *s);
/**
 */
void sha1_writebyte(sha1nfo *s, uint8_t data);
/**
 */
void sha1_write(sha1nfo *s, const char *data, size_t len);
/**
 */
uint8_t* sha1_result(sha1nfo *s);
/**
 */
void sha1_initHmac(sha1nfo *s, const uint8_t* key, int keyLength);
/**
 */
uint8_t* sha1_resultHmac(sha1nfo *s);


/* code */
#define SHA1_K0  0x5a827999
#define SHA1_K20 0x6ed9eba1
#define SHA1_K40 0x8f1bbcdc
#define SHA1_K60 0xca62c1d6

void sha1_init(sha1nfo *s) {
    s->state[0] = 0x67452301;
    s->state[1] = 0xefcdab89;
    s->state[2] = 0x98badcfe;
    s->state[3] = 0x10325476;
    s->state[4] = 0xc3d2e1f0;
    s->byteCount = 0;
    s->bufferOffset = 0;
}

uint32_t sha1_rol32(uint32_t number, uint8_t bits) {
    return ((number << bits) | (number >> (32-bits)));
}

void sha1_hashBlock(sha1nfo *s) {
    uint8_t i;
    uint32_t a,b,c,d,e,t;
    
    a=s->state[0];
    b=s->state[1];
    c=s->state[2];
    d=s->state[3];
    e=s->state[4];
    for (i=0; i<80; i++) {
        if (i>=16) {
            t = s->buffer[(i+13)&15] ^ s->buffer[(i+8)&15] ^ s->buffer[(i+2)&15] ^ s->buffer[i&15];
            s->buffer[i&15] = sha1_rol32(t,1);
        }
        if (i<20) {
            t = (d ^ (b & (c ^ d))) + SHA1_K0;
        } else if (i<40) {
            t = (b ^ c ^ d) + SHA1_K20;
        } else if (i<60) {
            t = ((b & c) | (d & (b | c))) + SHA1_K40;
        } else {
            t = (b ^ c ^ d) + SHA1_K60;
        }
        t+=sha1_rol32(a,5) + e + s->buffer[i&15];
        e=d;
        d=c;
        c=sha1_rol32(b,30);
        b=a;
        a=t;
    }
    s->state[0] += a;
    s->state[1] += b;
    s->state[2] += c;
    s->state[3] += d;
    s->state[4] += e;
}

void sha1_addUncounted(sha1nfo *s, uint8_t data) {
    uint8_t * const b = (uint8_t*) s->buffer;
#ifdef SHA_BIG_ENDIAN
    b[s->bufferOffset] = data;
#else
    b[s->bufferOffset ^ 3] = data;
#endif
    s->bufferOffset++;
    if (s->bufferOffset == BLOCK_LENGTH) {
        sha1_hashBlock(s);
        s->bufferOffset = 0;
    }
}

void sha1_writebyte(sha1nfo *s, uint8_t data) {
    ++s->byteCount;
    sha1_addUncounted(s, data);
}

void sha1_write(sha1nfo *s, const char *data, size_t len) {
    for (;len--;) sha1_writebyte(s, (uint8_t) *data++);
}

void sha1_pad(sha1nfo *s) {
    // Implement SHA-1 padding (fips180-2 禮5.1.1)
    
    // Pad with 0x80 followed by 0x00 until the end of the block
    sha1_addUncounted(s, 0x80);
    while (s->bufferOffset != 56) sha1_addUncounted(s, 0x00);
    
    // Append length in the last 8 bytes
    sha1_addUncounted(s, 0); // We're only using 32 bit lengths
    sha1_addUncounted(s, 0); // But SHA-1 supports 64 bit lengths
    sha1_addUncounted(s, 0); // So zero pad the top bits
    sha1_addUncounted(s, s->byteCount >> 29); // Shifting to multiply by 8
    sha1_addUncounted(s, s->byteCount >> 21); // as SHA-1 supports bitstreams as well as
    sha1_addUncounted(s, s->byteCount >> 13); // byte.
    sha1_addUncounted(s, s->byteCount >> 5);
    sha1_addUncounted(s, s->byteCount << 3);
}

uint8_t* sha1_result(sha1nfo *s) {
    // Pad to complete the last block
    sha1_pad(s);
    
#ifndef SHA_BIG_ENDIAN
    // Swap byte order back
    int i;
    for (i=0; i<5; i++) {
        s->state[i]=
        (((s->state[i])<<24)& 0xff000000)
        | (((s->state[i])<<8) & 0x00ff0000)
        | (((s->state[i])>>8) & 0x0000ff00)
        | (((s->state[i])>>24)& 0x000000ff);
    }
#endif
    
    // Return pointer to hash (20 characters)
    return (uint8_t*) s->state;
}

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

void sha1_initHmac(sha1nfo *s, const uint8_t* key, int keyLength) {
    uint8_t i;
    memset(s->keyBuffer, 0, BLOCK_LENGTH);
    if (keyLength > BLOCK_LENGTH) {
        // Hash long keys
        sha1_init(s);
        for (;keyLength--;) sha1_writebyte(s, *key++);
        memcpy(s->keyBuffer, sha1_result(s), HASH_LENGTH);
    } else {
        // Block length keys are used as is
        memcpy(s->keyBuffer, key, keyLength);
    }
    // Start inner hash
    sha1_init(s);
    for (i=0; i<BLOCK_LENGTH; i++) {
        sha1_writebyte(s, s->keyBuffer[i] ^ HMAC_IPAD);
    }
}

uint8_t* sha1_resultHmac(sha1nfo *s) {
    uint8_t i;
    // Complete inner hash
    memcpy(s->innerHash,sha1_result(s),HASH_LENGTH);
    // Calculate outer hash
    sha1_init(s);
    for (i=0; i<BLOCK_LENGTH; i++) sha1_writebyte(s, s->keyBuffer[i] ^ HMAC_OPAD);
    for (i=0; i<HASH_LENGTH; i++) sha1_writebyte(s, s->innerHash[i]);
    return sha1_result(s);
}


void SignInit(SignContext *ctx, char *src) {
    ctx->p = malloc(sizeof(char)*strlen(src)+1);
    memcpy(ctx->p, src, sizeof(char)*strlen(src));
    ctx->p[strlen(src)] = '\0';
}

void GenSignature(SignContext *ctx)
{
    memset(ctx->result, 0, sizeof(char)*512);

    int i;
    
//    for (i=0; i<strlen(ctx->p); i++) {
//        if(i==0)continue;
//        if (i%2==0) {
//            ctx->p[i] = ctx->p[i]^ctx->p[i-1];
//        }
//    }

    char SHA1String[512];
    bzero(SHA1String, sizeof(char)*512);

    sha1nfo s;
    sha1_init(&s);
    sha1_write(&s, ctx->p, strlen(ctx->p));
    uint8_t* hash = sha1_result(&s);
    for (i=0; i<20; i++) {
        sprintf(SHA1String+strlen(SHA1String), "%02x", hash[i]);
    }
    MD5_CTX mdContext;
    unsigned int len = strlen(SHA1String);
    MD5Init (&mdContext);
    MD5Update (&mdContext, (unsigned char *)SHA1String, len);
    MD5Final (&mdContext);
    for (i = 0; i < 16; i++)
        sprintf(ctx->result+strlen(ctx->result), "%02x", mdContext.digest[i]);
    free(ctx->p);
}

void a(char *s) {
    for (int i=0;i<strlen(s);i++) {
        if (i==0) continue;
        //97 ~ 122  65 ~ 90
        if (!((s[i]>=65&&s[i]<=90)||(s[i]>=97&&s[i]<=122))) continue;
        if (i%2==0) s[i] = s[i] ^ 32;
        else if (i%5==0) continue;
    }
}

char* GetString()
{
    return "Hello World";
}

void CtoM(const char *src,const char *key,char *output)
{
    int m1[strlen(src)],k1[strlen(key)],c1[strlen(src)],i,j;
    for(i=0;i<strlen(key);i++)
        k1[i]=key[i]-'a';
    for(j=0;j<strlen(src);j++)
    {
        c1[j]=src[j]-'a';

        if (src[strlen(src)-1] == 0x01)
            m1[j]=(c1[j]+k1[j%strlen(key)]-26)%26;
        else
            m1[j]=(c1[j]-k1[j%strlen(key)]+26)%26;
        output[j]=m1[j]+'a';
        printf("%c------%c\n",src[j],output[j]);
    }
    output[strlen(src)] = 0x01;
    output[strlen(src)+1] = '\0';
    
    
    
    
//    int m1[50],k1[10],c1[50],i,j;
//    for(i=0;i<strlen(k);i++)
//        k1[i]=k[i]-'a';
//    for(j=0;j<strlen(m);j++)
//    {
//        m1[j]=m[j]-'a';
//        c1[j]=(m1[j]+k1[j%strlen(k)])%26;
//        c[j]=c1[j]+'a';
//        printf("%c------%c\n",m[j],c[j]);
//    }
    
    
    
}
