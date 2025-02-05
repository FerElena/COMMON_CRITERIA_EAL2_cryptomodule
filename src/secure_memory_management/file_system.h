/**
 * @file file_system.h
 * @brief File containing all the necessary function headers and definitions for the cryptographic library file system.
 * it uses a single data file containing the metadata and the data , and grants data integrity , and prevents malicius 
 * data corruption, it is desgined to be used on embeded systems, continius file deletion and updating with diferent sizes
 * can cause fragmentation, having a negative impact on performance, so it is recomended to not hard abuse update and delete funtions
 * the optimal dessign is create all the needed files for the system on which you are implementing it, and not updating them for more size 
 * than the already existing size they have 
 *
 * the data buffer global variable is reutilized internally by the file_system, so when user reads data, it is expected to put the read data in a diferent memory buffer
 * else, the data buffer will be overwritten on the next file system operation that is performed!
 */

#ifndef FILESYSTEM_H
#define FILESYSTEM_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <stdint.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "../crypto/CRC_Galileo.h"
#include "../crypto/AES_OFB.h"
#include "../crypto/AES_CORE.h"
#include "../prng/random_number.h"

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

/**
 * @brief The maximum size of the file system , it can be modified accordingly to other constants , currently 40MB
 *
 */
#define MAX_FILESYSTEM_SIZE  41943040 

/**
 * @brief  Max number of files in the file system, it can be modified accordingly to other constants
 */
#define MAX_FILES 10000

/**
 * @brief Max length of the filename
 */
#define MAX_FILENAME_LENGTH 100

/**
 * @brief Max length of the data associated with a filename, it can be modified accordingly to other constants
 */
#define MAX_FILE_DATA 2000000

/**
 * @brief Initialization file system mode to create it
 */
#define MODE_INIT 0

/**
 * @brief Initialization file system mode when the system exists
 */
#define MODE_LOAD 1

#define IS_CSP 1
#define NOT_CSP 0

#define SYSTEM_CLOSE 0
#define SYSTEM_OPEN 1

#define NO_METADATA 0
#define SAVE_METADATA 1

#define CIPHER_ON 1
#define CIPHER_OFF 0


/**
 * @brief File system operation generic error code
 */
#define FS_ERROR -1000

/**
 * @brief File system operation correct code
 */
#define FILESYSTEM_OK 1001

/**
 * @brief No file system files exists error code
 */
#define FS_NO_FILESYSTEM_FILES -1001

/**
 * @brief Incorrect file system mode error code
 */
#define FS_INCORRECT_MODE -1002

/**
 * @brief No filename error code
 */
#define FS_NOT_EXISTANT_FILENAME -1003

/**
 * @brief Max filenames in file system error code
 */
#define FS_MAX_FILENAMES_REACHED -1004

/**
 * @brief Incorrect arguments error code
 */
#define FS_INCORRECT_ARGUMENT_ERROR -1005

/**
 * @brief Filename creation error code
 */
#define FS_FILENAME_ALREADYEXIST_ERROR -1006

/**
 * @brief Max size reached in file system error code
 */
#define FS_MAX_SIZE_REACHED -1007

/**
 * @brief Data modification without prior authorization
 * 
 */
#define FS_CORRUPTED_DATA -1008

// buffer to get the data out of the file

extern unsigned char FS_data_buffer[MAX_FILE_DATA]; // CSP

extern unsigned char FS_cipher_key[32]; //CSP

/* Type definitions ................................................. */

/**
 * @brief Filename struct to manage a single file in the file system, it is supposed to content the name of the file,
 * the length of the file name, the size of the file in the system, and the offset where the file starts in the system.
 *
 */
typedef struct
{
    uint8_t IV[16];                             /**< File -IV in case it is CSP, and setup cipher on */
    unsigned int offset;                        /**< Position in the file system, where the data related with the filename starts */
    uint32_t CRC_32_checksum;                   /**< Checksum for file integrity */
    size_t size;                                /**< Size of the data associated with the filename */
    size_t filename_length;                     /**< Parameter size */
    uint8_t isCSP;                              /**< Parameter to determine if it is CSP */
    unsigned char filename[MAX_FILENAME_LENGTH]; /**< Name of the file, supposed to be a string of max 50 size */
} FileAllocation;

/**
 * @brief File system struct to manage all the files stored and the file system/metadata files, it contents
 * the number of files in the system currently, and array of FilleAllocation structs , a pointer to the
 * disk with the data of the files, and a lastly a pointer to the metadata disk
 *
 */
typedef struct
{
    unsigned int num_filenames;                  /**< Current num of descriptors of the file*/
    FileAllocation allocations[MAX_FILES];       /**< Array containing all the files in the file system*/
    FILE *FS_data_descriptor;                      /**< File with the stored data of all the file system*/
    unsigned char file_system_rpath[512];         /** relative path to the file storing all the data in the OS*/
    uint8_t filesystem_state;                     /** parameter to indicate if the filesystem is open or close */
    uint16_t filesystem_calls;                    /** number of stdin calls to fflush stdin */
    uint8_t cipher_mode;                          /** current mode of the file_system, should only be setup once */
} File_System;


/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief Partition the array during the quicksort process.
 *
 * This function takes the last element as a pivot, places the pivot element at its
 * correct position in sorted array, and places all smaller elements to the left
 * of the pivot and all greater elements to the right of the pivot.
 *
 *
 * @param arr Array of FileAllocation structs that needs to be partitioned.
 * @param low Starting index of the partition range.
 * @param high Ending index of the partition range.
 * @return The index of the pivot element after partition.
 */

int FS_partition(FileAllocation arr[], int low, int high);

/**
 * @brief Main quicksort function to sort FileAllocation structs by their offset.
 *
 * This function sorts the elements of the `arr` array in-place using the quicksort algorithm.
 * The sorting is done based on the offset value of each FileAllocation struct.
 *
 *
 * @param arr Array of FileAllocation structs that needs to be sorted.
 * @param low Starting index for the sort range.
 * @param high Ending index for the sort range.
 */

void FS_quicksort(FileAllocation arr[], int low, int high);


/**
 * @brief Saves the metadata memory block into the metadata file system
 * The purpose of this function is to saves the metadata updated, so it can be used in the next file system
 * operation, it is important to being used every single time an operation which modifies the file_system_metadata is made
 * else consecuent operations will result in error. it also actualices the global variable with the metadata.
 *
 *
 * @param metadata_file File system metadata filename
 */
int FS_saveall_metadatablock();

int FS_checkdatasave(unsigned int IsCSP,uint8_t Metadata_update);

/**
 * @brief Open the file system
 * The purpose of this function is to open the file system and start operating with it. Thhe file system can
 * be opened in 2 modes (init mode than creates the file system, or load mode which uses an existing file system)
 * init mode is used only for testing purposes, as the file_system will be given with the cryptolibrary already
 * created in most cases. If used on Load_Mode, the system will load metadata in the RAM, and open file descriptors
 * so operations on the can be made.
 *
 * @param mode Initialization mode (0 or 1)
 * @return The result of the operation
 *
 * @errors
 * @error{ ERROR 1, Returns FS_NO_FILESYSTEM_FILES if the file system file descriptors are NULL}
 * @error{ ERROR 2, Returns FS_INCORRECT_MODE if the open mode is incorrect}
 */
int API_FS_initiate_file_system(unsigned int mode , unsigned char *filesystem_route , size_t filesystem_route_length);

int API_FS_setup_cipher(uint8_t mode,uint8_t *fs_Key);

/**
 * @brief Checks if the filename exists
 * The purpose of this function is to search the filename into the metadata to make operations with it, if 
 * the file exists, it will return the index of the file in the metadata structure, if it does not, it will
 * return -3
 *
 *
 * @param filename Filename to search
 * @param filename_length Filename length
 * @return The Metadatablock index related to the filename
 *
 * @errors
 * @error{ ERROR 1, Returns FS_NOT_EXISTANT_FILENAME if the filename is not in the file system}
 */
int API_FS_exists_file(unsigned char *filename, size_t filename_length);

/**
 * @brief Create a filename data object
 * The purpose of this function is to create a new block in the file system to store information , it uses a
 * quicksort algorithm so files which are already in the systems gets sorted according to their offset. So
 * consecuent operations can be easier to perform. Once quicksort have been realiced, it inserts the new file in the
 * system if it does not already exists, or have suspicious parameters.
 *
 * @methodOfUse{This function is invoked by the persistence_library.c and API.c}
 *
 * @param filename Filename
 * @param filename_length Filename length
 * @param data Data to store
 * @param data_size Data size
 * @param isCSP Parameter to indicate if a parameter is CSP or is not
 * @return Result of the operation
 *
 * @errors
 * @error{ ERROR 1, Returns FS_MAX_FILENAMES_REACHED if the metadata cannot allocate more information}
 * @error{ ERROR 2, Returns FS_INCORRECT_ARGUMENT_ERROR if the provided arguments are incorrect}
 * @error{ ERROR 3, Returns FS_FILENAME_ALREADYEXIST_ERROR if the filename is in the file system
 * @error{ ERROR 4, Returns FS_MAX_SIZE_REACHED if the file system cannot allocate more information}
 */
int API_FS_create_file_data(unsigned char *filename, size_t filename_length, unsigned char *data, size_t data_size, uint8_t isCSP);

/**
 * @brief Securely zeroize a file
 * The purpose of this function is to securely erase a file by overwriting its contents multiple times using
 * Schneier's patterns to make data recovery more difficult. If the file is marked as CSP (Critical Security Parameters),
 * an integrity check is performed before zeroization. The function handles encrypted CSP files by decrypting them before 
 * checking the integrity, and then proceeds to overwrite the data six times with specific patterns.
 *
 * @methodOfUse{This function is invoked by persistence_library.c and API.c}
 *
 * @param filename Filename of the file to zeroize
 * @param filename_length Length of the filename
 * @return Result of the zeroization process
 *
 * @errors
 * @error{ ERROR 1, Returns FS_INCORRECT_ARGUMENT_ERROR if the filename is NULL or too long}
 * @error{ ERROR 2, Returns FS_NO_FILESYSTEM_FILES if the filesystem is not initialized or closed}
 * @error{ ERROR 3, Returns FS_ERROR if there is an issue reading or writing the file}
 * @error{ ERROR 4, Returns FS_CORRUPTED_DATA if the file's integrity check fails before zeroization}
 */

int API_FS_zeroize_file(unsigned char *filename,size_t filename_length);

/**
 * @brief Delete and zeroize a file system block
 * The purpose of this function is to zeroize a file system block to avoid data breach, and then delete it from the metadata block,
 * it also actualices the metadata accordingly to the result of the operation.
 *
 * @methodOfUse{This function is invoked by the persistence_library.c and API.c}
 *
 * @param filename Filename to be deleted
 * @param filename_length length of the name of the filename to delete
 * @return Result of the operation
 *
 * @errors
 * @error{ ERROR 1, Returns FS_NOT_EXISTANT_FILENAME if the filename does not exist in the file system}
 */
int API_FS_delete_file(unsigned char *filename , size_t filename_length);

/**
 * @brief Get a file system block
 * The purpose of this function is to get a block into the file system associated with a filename, it returns
 * the data on a pointer to a global buffer of data which is reutilized
 * 
 *
 *
 * @param filename Filename
 * @param filename_length length of the name of the filename
 * @param buffer_out pointer to store a pointer to the global buffer in which de data is stored
 * @param data_length length of the data stored in the buffer_out
 * @return The data block required
 * @errors
 * @error{ ERROR 1, Returns NULL if the filename does not exist in the file system}
 */
int API_FS_read_file_data(unsigned char *filename,size_t filename_length,unsigned char **buffer_out,unsigned int *data_length );

/**
 * @brief Rename a file in the filesystem.
 * 
 * The purpose of this function is to rename an existing file in the filesystem by replacing its current name 
 * with a new name. The function performs validation on the input arguments, ensuring that the filenames are 
 * valid and that the filesystem is in an active state. It also handles thread safety with a mutex and performs 
 * a secure save of metadata if the file contains Critical Security Parameters (CSP). If the file does not exist 
 * or if there is an error in the renaming process, it returns an appropriate error code.
 * 
 * @methodOfUse{This function is invoked by file system management modules to rename files in the system.}
 * 
 * @param old_filename The current name of the file.
 * @param old_filename_length The length of the current filename.
 * @param new_filename The new name for the file.
 * @param new_filename_length The length of the new filename.
 * @return Result of the operation.
 * 
 * @errors
 * @error{ ERROR 1, Returns FS_INCORRECT_ARGUMENT_ERROR if the provided arguments are incorrect.}
 * @error{ ERROR 2, Returns FS_NO_FILESYSTEM_FILES if the filesystem is not initialized or is closed.}
 * @error{ ERROR 3, Returns FS_NOT_EXISTANT_FILENAME if the file to be renamed does not exist.}
 * @error{ ERROR 4, Returns FS_ERROR if an error occurs while saving metadata.}
 * @error{ ERROR 5, Returns FILESYSTEM_OK if the rename operation was successful.}
 */
int API_FS_rename_file(unsigned char *old_filename , size_t old_filename_length , unsigned char *new_filename , size_t new_filename_length);

int find_space_for_data(size_t data_size,unsigned int exclude_index);

/**
 * @brief Update the data form a file system block
 * The purpose of this function is to update the information allocated in a determined file system block
 * in the case the new data of a file is bigger than the current data, it may needs to reallocate the
 * data of the file, in the system, in that case the algorithm will search for a bigger space avaible in the 
 * file system
 *
 *
 * @param filename Filename
 * @param data New data
 * @param data_size New data size
 * @return Result of the operation
 */
int API_FS_update_file_data(unsigned char *filename, size_t filename_length,unsigned char *data, size_t data_size);

/**
 * @brief Zeroize the library file system
 * The purpose of this function is to zeroize all the file system blocks when the library is in ERROR_STATE, or when 
 * a cryptooficer sends a zeroization packets, it zeroizes completly the system, and a new initialization
 * will be needed in order for the system to work again.
 *
 *
 * @return Result of the operation
 */
int API_FS_zeroize_file_system();

/**
 * @brief Write a buffer into a file, in a determined position, not suitable for CSPs
 * 
 *
 *
 * @param filename file name string
 * @param buffer Buffer where is the information to be written
 * @param buffer_size Buffer size
 * @param position Position where the information will be written
 * @return The result of the operation
 *
 * @errors
 * @error{ ERROR 1, Returns FS_NOT_EXISTANT_FILENAME if the filename does not exist in the file system}
 * @error{ ERROR 2, Returns FS_MAX_SIZE_REACHED if the buffer size exceeds file space}
 * @error{ ERROR 3, Returns FS_ERROR if there is an error writing buffer to file}

 */
int API_FS_write_buffer_to_file(unsigned char *filename,size_t filename_length, unsigned char *buffer_in, size_t buffer_size, size_t position);

/**
 * @brief read a size of the file_system, and stores it in a buffer, buffer must be correct size, or there will be a seg fault, not suitable for CSPs
 * 
 *
 *
 * @param filename file name string
 * @param buffer Buffer where is the information to be read
 * @param read_size Information size to be read
 * @param position Position where the information will be read
 * @return The result of the operation
 *
 * @errors
 * @error{ ERROR 1, Returns FS_NOT_EXISTANT_FILENAME if the filename does not exist in the file system}
 * @error{ ERROR 2, Returns FS_MAX_SIZE_REACHED if the read position is invalid}
 * @error{ ERROR 3, Returns FS_MAX_SIZE_REACHED if the read size is invalid}
 * @error{ ERROR 4, Returns FS_INCORRECT_ARGUMENT_ERROR if there is an error moving the file pointer}
 * @error{ ERROR 5, Returns FS_ERROR if there is an error reading the file}
 */
int API_FS_read_buffer_from_file(unsigned char *filename,size_t filename_length, unsigned char *buffer_out, size_t read_size, size_t position);

void API_FS_Close_filesystem();

//testing functions

void print_bytes(unsigned char *filename,size_t filename_length, int num_bytes);

void print_files();

void print_files_content();

#endif
