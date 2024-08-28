#ifndef CRC_GALILEO
#define CRC_GALILEO

#include <stdint.h>
#include <stddef.h>

static const unsigned int crc32tab[256];
static const unsigned int crc24tab[256];
static const uint16_t crc16tab[256];

unsigned int crc_32(const unsigned char *buf, size_t len);
unsigned int crc_24(const unsigned char *buf, size_t len);
uint16_t crc_16(const unsigned char  *buf, size_t len);


#endif