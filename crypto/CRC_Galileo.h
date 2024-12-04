/**
 * @file CRC_Galileo.h
 * @brief File containing all the function headers of CRC.
 */

#ifndef CRC_GALILEO
#define CRC_GALILEO

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdint.h>
#include <stddef.h>

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @file crc_tables.h
 * @brief CRC (Cyclic Redundancy Check) lookup tables for various CRC algorithms.
 *
 * This file contains precomputed CRC tables for CRC32, CRC24, and CRC16 algorithms,
 * used to accelerate the calculation of CRC checksums.
 */


/**
 * @brief Precomputed CRC32 table.
 *
 * This table contains 256 precomputed values for CRC32 calculations. It is used in conjunction
 * with the CRC32 algorithm to quickly compute the checksum of a data stream.
 * 
 * The polynomial used is 0x04C11DB7 (the standard CRC32 polynomial).
 * 
 * @note Each entry represents the result of a single-byte XOR operation followed by 8 iterations
 * of the CRC algorithm.
 */

static const unsigned int crc32tab[256];
/**
 * @brief Precomputed CRC24 table.
 *
 * This table contains 256 precomputed values for CRC24 calculations. It is used to speed up
 * the calculation of CRC24 checksums for data streams.
 * 
 * The polynomial used for CRC24 is 0x864CFB.
 * 
 * @note Each entry represents the result of a single-byte XOR operation followed by 8 iterations
 * of the CRC algorithm.
 */
static const unsigned int crc24tab[256];

/**
 * @brief Precomputed CRC16 table.
 *
 * This table contains 256 precomputed values for CRC16 calculations, based on the polynomial
 * 0xA001. It is commonly used in applications such as Modbus communication.
 * 
 * @note Each entry in the table represents the result of a CRC operation on a single byte
 * of data.
 */
static const uint16_t crc16tab[256];

/**
 * @brief Computes the CRC-32 checksum of a buffer.
 *
 * This function calculates the CRC-32 checksum of the given buffer using a predefined lookup table.
 *
 * @param buf Pointer to the input buffer.
 * @param len Length of the input buffer in bytes.
 * @return The CRC-32 checksum value.
 */

unsigned int crc_32(const unsigned char *buf, size_t len);

/**
 * @brief Computes the CRC-24 checksum of a buffer.
 *
 * This function calculates the CRC-24 checksum of the given buffer using a predefined lookup table.
 *
 * @param buf Pointer to the input buffer.
 * @param len Length of the input buffer in bytes.
 * @return The CRC-24 checksum value.
 */

unsigned int crc_24(const unsigned char *buf, size_t len);

/**
 * @brief Computes the CRC-16 checksum of a buffer.
 *
 * This function calculates the CRC-16 checksum of the given buffer using a predefined lookup table.
 *
 * @param buf Pointer to the input buffer.
 * @param len Length of the input buffer in bytes.
 * @return The CRC-16 checksum value.
 */

uint16_t crc_16(const unsigned char  *buf, size_t len);


#endif