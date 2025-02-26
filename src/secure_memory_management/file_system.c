/**
 * @file file_system.c
 * @brief File containing all the functions for the cryptographic library file system
 */

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/
#include "file_system.h"

/****************************************************************************************************************
 * Global variables definition
 ****************************************************************************************************************/
File_System MetadataBlock; // Global struct containing the metadata of the file system

pthread_mutex_t FS_mutex = PTHREAD_MUTEX_INITIALIZER; // semaphore to keep the filesystem data resistant

unsigned char FS_data_buffer[MAX_FILE_DATA]; // CSP shared data buffer wich is overwriten with consecutive FS_functions calls(except API_FS_write_buffer_to_file and API_FS_read_buffer_from_file)
                                             // the data in this buffer is supposed to be copied to another buffer which is not going to be overwriten by consecutive operations
                                             // FS does not really support threads as this buffer can be overwriten with 2 consecutive FS calls
unsigned char FS_cipher_key[32];
// Schneier patrons for secure zeroization making it harder for data recovery
static const unsigned char Schneier_patterns[] = {0x00, 0xFF, 0xAA, 0x55, 0xAA, 0x55};

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

// AUX FUNCTIONS

// function to partitionate an array for quicksort algorithm
int FS_partition(FileAllocation arr[], int low, int high)
{
    int pivot = arr[high].offset; // Choose the offset of the last element as the pivot
    int i = (low - 1);            // Index of the smaller element

    for (int j = low; j <= high - 1; j++)
    {
        // If the current element is smaller than the pivot
        if (arr[j].offset < pivot)
        {
            i++;
            // Swap arr[i] and arr[j]
            FileAllocation temp = arr[i];
            arr[i] = arr[j];
            arr[j] = temp;
        }
    }
    // Swap arr[i + 1] and arr[high] (or pivot)
    FileAllocation temp = arr[i + 1];
    arr[i + 1] = arr[high];
    arr[high] = temp;
    return (i + 1);
}

// Main function for quicksort the Metadata Block , its not a common quicksort, it is optimized for this file system depending on the file offsets
void FS_quicksort(FileAllocation arr[], int low, int high)
{
    if (low < high)
    {
        // partitioningIndex is the index where the pivot element is placed at its correct position
        int partitioningIndex = FS_partition(arr, low, high);

        // Separately sort the elements before and after the partitioning index
        FS_quicksort(arr, low, partitioningIndex - 1);
        FS_quicksort(arr, partitioningIndex + 1, high);
    }
}

// function to wrie the Metadata block struct into the filesystem
int FS_saveall_metadatablock()
{
    // Save the metadata in the global variable, to the metadata_file , this function supposses that the filesystem is already opened
    if (MetadataBlock.FS_data_descriptor == NULL)
    {
        return FS_NO_FILESYSTEM_FILES;
    }
    fseek(MetadataBlock.FS_data_descriptor, 0, SEEK_SET);
    size_t write_bytes = fwrite(&MetadataBlock, 1, sizeof(MetadataBlock), MetadataBlock.FS_data_descriptor); // write all metadata from position 0 in the file_system

    if (write_bytes != sizeof(MetadataBlock))
    {
        return FS_ERROR;
    }
    return FILESYSTEM_OK;
}

// function to secure correct save of the write buffer in case of CSP garantizing data integrity via costing more execution time
int FS_checkdatasave(unsigned int IsCSP, uint8_t Metadata_update)
{
    int result = 1;
    if (IsCSP && MetadataBlock.filesystem_state == SYSTEM_OPEN)
    {
        if (Metadata_update)
        {
            result = FS_saveall_metadatablock();
        }
        fflush(MetadataBlock.FS_data_descriptor);
        return FILESYSTEM_OK && result;
    }
    else if (MetadataBlock.filesystem_state == SYSTEM_OPEN)
    {
        MetadataBlock.filesystem_calls++;
        if (MetadataBlock.filesystem_calls >= 256)
        {
            if (Metadata_update)
                result = FS_saveall_metadatablock();

            fflush(MetadataBlock.FS_data_descriptor);
            MetadataBlock.filesystem_calls = 0;
        }
        return FILESYSTEM_OK && result;
    }
    else
        return FS_ERROR;
}

// FS FUNCTIONS

// function to initialise the file_system for first time, or consecutive time
int API_FS_initiate_file_system(unsigned int mode, unsigned char *filesystem_route, size_t filesystem_route_length)
{
    if (filesystem_route == NULL || filesystem_route_length >= 512)
    {
        return FS_INCORRECT_ARGUMENT_ERROR;
    }
    pthread_mutex_lock(&FS_mutex);

    if (mode == MODE_INIT) // we intialice the file for the first time, or we reset the current file_system
    {
        memcpy(MetadataBlock.file_system_rpath, filesystem_route, filesystem_route_length);
        MetadataBlock.file_system_rpath[filesystem_route_length] = '\0'; // secure null character at end of route
        MetadataBlock.FS_data_descriptor = fopen(MetadataBlock.file_system_rpath, "wb+");

        if (MetadataBlock.FS_data_descriptor == NULL)
        { // return error if cannot open file
            pthread_mutex_unlock(&FS_mutex);
            return FS_NO_FILESYSTEM_FILES;
        }

        // configure Metadata parameters for Initialization mode
        fseek(MetadataBlock.FS_data_descriptor, MAX_FILESYSTEM_SIZE - 1 + sizeof(MetadataBlock), SEEK_SET);
        MetadataBlock.num_filenames = 0;
        MetadataBlock.allocations[0].offset = 0;
        MetadataBlock.allocations[0].size = 0;
        MetadataBlock.filesystem_state = SYSTEM_OPEN;
        MetadataBlock.filesystem_calls = 0;

        size_t write_bytes = fwrite("", 1, 1, MetadataBlock.FS_data_descriptor);
        if (write_bytes != 1)
        {
            fclose(MetadataBlock.FS_data_descriptor);
            MetadataBlock.filesystem_state = SYSTEM_CLOSE;
            pthread_mutex_unlock(&FS_mutex);
            return FS_ERROR;
        }

        rewind(MetadataBlock.FS_data_descriptor);
        pthread_mutex_unlock(&FS_mutex);
        return FILESYSTEM_OK; // system correctly initialized in first init
    }

    else if (mode == MODE_LOAD) // gets the metadata from the metadata file, into the MetadataBlock
    {
        memcpy(MetadataBlock.file_system_rpath, filesystem_route, filesystem_route_length);
        MetadataBlock.file_system_rpath[filesystem_route_length] = '\0'; // secure null character at end of route
        FILE *auxf = fopen(MetadataBlock.file_system_rpath, "rb+");

        if (auxf == NULL)
        { // return error if cannot open file
            pthread_mutex_unlock(&FS_mutex);
            return FS_NO_FILESYSTEM_FILES;
        }

        // load Metadata from disk into RAM
        fseek(auxf, 0, SEEK_SET);
        size_t read_bytes = fread(&MetadataBlock, sizeof(MetadataBlock), 1, auxf);
        memcpy(MetadataBlock.file_system_rpath, filesystem_route, filesystem_route_length);
        MetadataBlock.file_system_rpath[filesystem_route_length] = '\0'; // secure null character at end of route
        MetadataBlock.filesystem_state = SYSTEM_OPEN;
        MetadataBlock.filesystem_calls = 0;
        MetadataBlock.FS_data_descriptor = auxf;

        if (read_bytes != 1)
        {
            fclose(MetadataBlock.FS_data_descriptor);
            MetadataBlock.filesystem_state = SYSTEM_CLOSE;
            pthread_mutex_unlock(&FS_mutex);
            return FS_ERROR;
        }

        pthread_mutex_unlock(&FS_mutex);
        return FILESYSTEM_OK; // system correctly open
    }
    else
    { // if incorrect mode
        pthread_mutex_unlock(&FS_mutex);
        return FS_INCORRECT_MODE;
    }
}

int API_FS_setup_cipher(uint8_t mode, uint8_t *fs_Key)
{
    if (mode == CIPHER_ON)
    {
        MetadataBlock.cipher_mode = CIPHER_ON;
        memcpy(FS_cipher_key, fs_Key, 32);
        return 1;
    }
    else if (mode == CIPHER_OFF)
    {
        MetadataBlock.cipher_mode = CIPHER_OFF;
        return 2;
    }
    else
    {
        return 0;
    }
}

int API_FS_exists_file(unsigned char *filename, size_t filename_length) // auxiliar function to find the position of an existing file_Descriptor
{
    for (int i = 0; i < MetadataBlock.num_filenames; i++)
    {
        if ((memcmp(MetadataBlock.allocations[i].filename, filename, MetadataBlock.allocations[i].filename_length) == 0) && MetadataBlock.allocations[i].filename_length == filename_length)
        {
            return i; // return the position of the descriptor
        }
    }
    return FS_NOT_EXISTANT_FILENAME; // return error if the descriptor was not found
}

// create a new file, and adds a data buffer
int API_FS_create_file_data(unsigned char *filename, size_t filename_length, unsigned char *data, size_t data_size, uint8_t isCSP)
{
    pthread_mutex_lock(&FS_mutex);
    int offset = 0, i;
    // Initialize new_allocation_index to the current number of descriptors. This might be updated later.
    unsigned int new_allocation_index = MetadataBlock.num_filenames;
    // Check if maximum number of users has been reached.
    if (new_allocation_index >= MAX_FILES)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_MAX_FILENAMES_REACHED;
    }
    // Check if the provided arguments are valid (e.g. valid length, data and filename are not NULL).
    if (filename_length > MAX_FILENAME_LENGTH || data_size > MAX_FILE_DATA || filename == NULL || data == NULL || isCSP > 1)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_INCORRECT_ARGUMENT_ERROR;
    }
    if (MetadataBlock.FS_data_descriptor == NULL || MetadataBlock.filesystem_state == SYSTEM_CLOSE)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_NO_FILESYSTEM_FILES;
    }
    // Check if the file descriptor already exists, you cannot create an already existing file!
    if (API_FS_exists_file(filename, filename_length) != FS_NOT_EXISTANT_FILENAME)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_FILENAME_ALREADYEXIST_ERROR;
    }
    // Check if the file can fit at offset 0. If the offset of the first descriptor is equal or larger than the new data size,
    // it means that the new file can fit at the beginning of the file (offset 0) (used for the case where file 0 have been erased at some point)
    if (MetadataBlock.num_filenames > 0 && MetadataBlock.allocations[0].offset >= data_size)
    {
        new_allocation_index = 0;
    }
    else
    {
        if (MetadataBlock.num_filenames > 1) // if there is more than 1 file, then quicksort the array depending on the file offsets (smaller offsets first, bigger offsets last)
        {
            FS_quicksort(MetadataBlock.allocations, 0, MetadataBlock.num_filenames - 1);
        }
        // If the file doesn't fit at offset 0, look for a suitable gap between existing files.
        for (i = 0; i < MetadataBlock.num_filenames; i++)
        {
            int next_offset = MetadataBlock.allocations[i].offset + MetadataBlock.allocations[i].size;
            // Check if the gap between current file and the next one is enough to fit the new file.
            if (MetadataBlock.allocations[i + 1].offset - next_offset >= data_size)
            {
                offset = next_offset;
                new_allocation_index = i + 1;
                break;
            }
        }
        // If no suitable gap was found between existing files, assign the new file at the end.
        if (i == MetadataBlock.num_filenames - 1)
        {
            offset = MetadataBlock.allocations[i].offset + MetadataBlock.allocations[i].size;
        }
    }
    // Check if there's enough space in the file to include the new data.
    if (offset + data_size > MAX_FILESYSTEM_SIZE)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_MAX_SIZE_REACHED;
    }
    // if is CSP, calculate checksum for integrity testing
    if (isCSP)
        MetadataBlock.allocations[new_allocation_index].CRC_32_checksum = crc_32(data, data_size);
    else
        MetadataBlock.allocations[new_allocation_index].CRC_32_checksum = 0;

    size_t write_bytes;
    // if cipher mode on, cipher the data before write it;
    if (isCSP && MetadataBlock.cipher_mode == CIPHER_ON)
    {
        API_RNG_fill_buffer_random(MetadataBlock.allocations[new_allocation_index].IV, AES_BLOCK_SIZE);
        API_CP_AESOFB_encryptdecrypt(data, data_size, FS_cipher_key, AES_KEY_SIZE_256, MetadataBlock.allocations[new_allocation_index].IV, FS_data_buffer);
        fseek(MetadataBlock.FS_data_descriptor, offset + sizeof(MetadataBlock), SEEK_SET);
        write_bytes = fwrite(FS_data_buffer, 1, data_size, MetadataBlock.FS_data_descriptor);
    }
    // else, just write on filesystem with no cipher
    else
    {
        fseek(MetadataBlock.FS_data_descriptor, offset + sizeof(MetadataBlock), SEEK_SET);
        write_bytes = fwrite(data, 1, data_size, MetadataBlock.FS_data_descriptor);
    }
    if (write_bytes != data_size)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_ERROR;
    }

    // Move existing allocations to make room for the new one.
    for (int j = MetadataBlock.num_filenames; j > new_allocation_index; j--)
    {
        MetadataBlock.allocations[j] = MetadataBlock.allocations[j - 1];
    }
    // Update the metadata of the new allocation.
    memcpy(MetadataBlock.allocations[new_allocation_index].filename, filename, filename_length);
    MetadataBlock.allocations[new_allocation_index].filename_length = filename_length;
    MetadataBlock.allocations[new_allocation_index].size = data_size;
    MetadataBlock.allocations[new_allocation_index].offset = offset;
    MetadataBlock.allocations[new_allocation_index].isCSP = isCSP;

    // Increase the number of descriptors since a new file was allocated.
    MetadataBlock.num_filenames++;

    // Save the changes to the metadata block.
    int save_result = FS_checkdatasave(MetadataBlock.allocations[new_allocation_index].isCSP, SAVE_METADATA);
    pthread_mutex_unlock(&FS_mutex);

    if (save_result)
        return FILESYSTEM_OK;

    else
        return FS_ERROR;
}

// Zeroizes a file
int API_FS_zeroize_file(unsigned char *filename, size_t filename_length)
{
    // Validate input parameters
    if (filename == NULL || filename_length > MAX_FILENAME_LENGTH)
    {
        return FS_INCORRECT_ARGUMENT_ERROR; // Invalid filename or length
    }
    // Ensure the filesystem is open and ready
    if (MetadataBlock.FS_data_descriptor == NULL || MetadataBlock.filesystem_state == SYSTEM_CLOSE)
    {
        return FS_NO_FILESYSTEM_FILES; // Filesystem not available
    }

    // Find the file in the filesystem
    int index = API_FS_exists_file(filename, filename_length);

    // Lock the filesystem to ensure exclusive access
    pthread_mutex_lock(&FS_mutex);

    size_t bytes_read = 0;  // Track bytes read
    int corrupted_data = 0; // Track data corruption

    // If the file is CSP, check its integrity
    if (MetadataBlock.allocations[index].isCSP)
    {
        // Seek to the correct offset and read the file data
        fseek(MetadataBlock.FS_data_descriptor, MetadataBlock.allocations[index].offset + sizeof(MetadataBlock), SEEK_SET);
        bytes_read = fread(FS_data_buffer, 1, MetadataBlock.allocations[index].size, MetadataBlock.FS_data_descriptor);
        if (bytes_read != MetadataBlock.allocations[index].size)
        {
            pthread_mutex_unlock(&FS_mutex);
            return FS_ERROR; // Error reading the file
        }
        // Decrypt the data if encryption is enabled
        if (MetadataBlock.cipher_mode == CIPHER_ON)
        {
            API_CP_AESOFB_encryptdecrypt(FS_data_buffer, MetadataBlock.allocations[index].size, FS_cipher_key, AES_KEY_SIZE_256, MetadataBlock.allocations[index].IV, FS_data_buffer);
        }
        // Verify data integrity via CRC32
        unsigned int New_CRC32 = crc_32(FS_data_buffer, MetadataBlock.allocations[index].size);
        corrupted_data = (New_CRC32 == MetadataBlock.allocations[index].CRC_32_checksum) ? 0 : 1;
    }

    // Zeroize the file using Schneier's secure patterns
    for (int i = 0; i < 6; i++)
    {
        // Overwrite the file with the current Schneier pattern
        fseek(MetadataBlock.FS_data_descriptor, MetadataBlock.allocations[index].offset + sizeof(MetadataBlock), SEEK_SET);
        for (int j = 0; j < MetadataBlock.allocations[index].size; FS_data_buffer[j++] = Schneier_patterns[i])
            ;
        size_t written_bytes = fwrite(FS_data_buffer, 1, MetadataBlock.allocations[index].size, MetadataBlock.FS_data_descriptor);
        if (written_bytes != MetadataBlock.allocations[index].size)
        {
            pthread_mutex_unlock(&FS_mutex);
            return FS_ERROR; // Error writing the file
        }
    }

    // Unlock the filesystem after zeroization
    pthread_mutex_unlock(&FS_mutex);

    // Return error if data corruption was detected, otherwise return success
    if (corrupted_data)
    {
        return FS_CORRUPTED_DATA;
    }
    return FILESYSTEM_OK;
}

// delete a file, and zeroizes it if it is a CSP
int API_FS_delete_file(unsigned char *filename, size_t filename_length)
{
    if (filename == NULL || filename_length > MAX_FILENAME_LENGTH)
    {
        return FS_INCORRECT_ARGUMENT_ERROR;
    }
    if (MetadataBlock.FS_data_descriptor == NULL || MetadataBlock.filesystem_state == SYSTEM_CLOSE)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_NO_FILESYSTEM_FILES;
    }

    int index = API_FS_exists_file(filename, filename_length);
    if ((index == FS_NOT_EXISTANT_FILENAME)) // check if files exists, you cannot delete a non existing file!
    {
        return FS_NOT_EXISTANT_FILENAME; // File descriptor does not exist.
    }
    // open file system
    pthread_mutex_lock(&FS_mutex);
    size_t bytes_read;

    // check for data corruption from external sources, even if it is corrupted, the file is deleted
    int corrupted_data = 0;
    if (MetadataBlock.allocations[index].isCSP)
    {
        fseek(MetadataBlock.FS_data_descriptor, MetadataBlock.allocations[index].offset + sizeof(MetadataBlock), SEEK_SET);
        bytes_read = fread(FS_data_buffer, 1, MetadataBlock.allocations[index].size, MetadataBlock.FS_data_descriptor);
        if (bytes_read != MetadataBlock.allocations[index].size)
        {
            pthread_mutex_unlock(&FS_mutex);
            return FS_ERROR;
        }
        // if cipher mode, decipher it
        if (MetadataBlock.allocations[index].isCSP && MetadataBlock.cipher_mode == CIPHER_ON)
        API_CP_AESOFB_encryptdecrypt(FS_data_buffer, MetadataBlock.allocations[index].size, FS_cipher_key, AES_KEY_SIZE_256, MetadataBlock.allocations[index].IV, FS_data_buffer);

        unsigned int New_CRC32 = crc_32(FS_data_buffer, MetadataBlock.allocations[index].size);
        corrupted_data = (New_CRC32 == MetadataBlock.allocations[index].CRC_32_checksum) ? 0 : 1;
    }

    // if the file to be deleted is a CSP, zeroizes it using the secure Schneier pattern, simultaneusly zeroizes data buffer used previusly for check data corruption
    if (MetadataBlock.allocations[index].isCSP)
    {
        for (int i = 0; i < 6; i++)
        {
            fseek(MetadataBlock.FS_data_descriptor, MetadataBlock.allocations[index].offset + sizeof(MetadataBlock), SEEK_SET);
            for (int j = 0; j < MetadataBlock.allocations[index].size; FS_data_buffer[j++] = Schneier_patterns[i])
                ;
            fwrite(FS_data_buffer, MetadataBlock.allocations[index].size, 1, MetadataBlock.FS_data_descriptor);
        }
    }

    // move every element after index one step to the left
    for (int i = index; i < MetadataBlock.num_filenames; i++)
    {
        MetadataBlock.allocations[i] = MetadataBlock.allocations[i + 1];
    }
    // decrease the number of descriptors
    MetadataBlock.num_filenames--;

    // save updated metadata
    int save_result = FS_checkdatasave(IS_CSP, SAVE_METADATA);
    pthread_mutex_unlock(&FS_mutex);
    if (corrupted_data)
        return FS_CORRUPTED_DATA; // unauthorized data modification before deletion

    else if (save_result)
        return FILESYSTEM_OK; // Successful deletion.

    else
        return FS_ERROR; // Unsuccessful deletion.
}

// read the entire data of a file, and returns it in the global buffer which is reutilized
int API_FS_read_file_data(unsigned char *filename, size_t filename_length, unsigned char **buffer_out, unsigned int *data_length)
{
    if (filename == NULL || filename_length > MAX_FILENAME_LENGTH || buffer_out == NULL || data_length == NULL)
    {
        return FS_INCORRECT_ARGUMENT_ERROR;
    }
    if (MetadataBlock.FS_data_descriptor == NULL || MetadataBlock.filesystem_state == SYSTEM_CLOSE)
    {
        return FS_NO_FILESYSTEM_FILES;
    }
    pthread_mutex_lock(&FS_mutex);

    int index = API_FS_exists_file(filename, filename_length);
    if (index != FS_NOT_EXISTANT_FILENAME) // if the user does exist
    {
        // read data from the filesystem
        fseek(MetadataBlock.FS_data_descriptor, MetadataBlock.allocations[index].offset + sizeof(MetadataBlock), SEEK_SET);
        size_t bytes_read = fread(FS_data_buffer, 1, MetadataBlock.allocations[index].size, MetadataBlock.FS_data_descriptor);
        if (bytes_read != MetadataBlock.allocations[index].size)
        {
            pthread_mutex_unlock(&FS_mutex);
            return FS_ERROR;
        }
        // if setup to cipher mode, we decipher it
        if (MetadataBlock.allocations[index].isCSP && MetadataBlock.cipher_mode == CIPHER_ON)
        API_CP_AESOFB_encryptdecrypt(FS_data_buffer, MetadataBlock.allocations[index].size, FS_cipher_key, AES_KEY_SIZE_256, MetadataBlock.allocations[index].IV, FS_data_buffer);

        *buffer_out = FS_data_buffer;                         // assign input parameter pointer, to the global data buffer
        *data_length = MetadataBlock.allocations[index].size; // assign input length pointer to the size of the file

        if (MetadataBlock.allocations[index].isCSP)
        {
            int New_CRC32 = crc_32(FS_data_buffer, MetadataBlock.allocations[index].size);
            int corrupted_data = (New_CRC32 == MetadataBlock.allocations[index].CRC_32_checksum) ? 0 : 1;
            if (corrupted_data)
            {
                pthread_mutex_unlock(&FS_mutex);
                return FS_CORRUPTED_DATA;
            }
        }
        int save_result = FS_checkdatasave(MetadataBlock.allocations[index].isCSP, NO_METADATA); // no need to save metadata as it is only a read from file
        pthread_mutex_unlock(&FS_mutex);
        if (save_result)
            return FILESYSTEM_OK; // return success in read the data operation
        else
            return FS_ERROR; // return error in operation
    }
    // else, user does not exists
    pthread_mutex_unlock(&FS_mutex);
    return FS_NOT_EXISTANT_FILENAME; // if the user does not exist, return ERROR
}

// update filename of a file

int API_FS_rename_file(unsigned char *old_filename, size_t old_filename_length, unsigned char *new_filename, size_t new_filename_length)
{
    if (old_filename == NULL || new_filename == NULL || old_filename_length > MAX_FILENAME_LENGTH || new_filename_length > MAX_FILENAME_LENGTH)
    {
        return FS_INCORRECT_ARGUMENT_ERROR;
    }
    if (MetadataBlock.FS_data_descriptor == NULL || MetadataBlock.filesystem_state == SYSTEM_CLOSE)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_NO_FILESYSTEM_FILES;
    }
    int index = API_FS_exists_file(old_filename, old_filename_length);
    pthread_mutex_lock(&FS_mutex);

    if (index == FS_NOT_EXISTANT_FILENAME)
    { // if file does not exists, return error code
        pthread_mutex_unlock(&FS_mutex);
        return FS_NOT_EXISTANT_FILENAME;
    }

    memcpy(MetadataBlock.allocations[index].filename, new_filename, new_filename_length);
    MetadataBlock.allocations[index].filename_length = new_filename_length;
    int save_result = FS_checkdatasave(MetadataBlock.allocations[index].isCSP, SAVE_METADATA); // if file is CSP, secure save Metadata
    pthread_mutex_unlock(&FS_mutex);
    if (save_result)
        return FILESYSTEM_OK; // correct rename of data
    else
        return FS_ERROR;
}

// update the old file data, at the same times it reallocs more memory iun disk if needed, if used with larger sizes it can fragment the disk, so not recomended to reuse if asking for more size
// it check the CRC before updatring the file content, so it is more secure to write on files, but slower. RECOMENDED FOR USE IF FILE IS CSP

int API_FS_update_file_data(unsigned char *filename, size_t filename_length, unsigned char *data, size_t data_size)
{
    if (filename == NULL || filename_length > MAX_FILENAME_LENGTH || data == NULL || data_size > MAX_FILE_DATA)
        return FS_INCORRECT_ARGUMENT_ERROR;
    if (MetadataBlock.FS_data_descriptor == NULL || MetadataBlock.filesystem_state == SYSTEM_CLOSE)
        return FS_NO_FILESYSTEM_FILES;

    int index = API_FS_exists_file(filename, filename_length);
    int save_result;
    if (index == FS_NOT_EXISTANT_FILENAME) // if file does not exists, return error code
        return FS_NOT_EXISTANT_FILENAME;

    pthread_mutex_lock(&FS_mutex);
    int current_offset = MetadataBlock.allocations[index].offset;
    int current_size = MetadataBlock.allocations[index].size;

    // check for posible data corruptions on old data before updating it
    int corrupted_data = 0;
    size_t bytes_trafic;
    if (MetadataBlock.allocations[index].isCSP) // checks for memory corruption before the write
    {
        fseek(MetadataBlock.FS_data_descriptor, current_offset + sizeof(MetadataBlock), SEEK_SET);
        bytes_trafic = fread(FS_data_buffer, 1, MetadataBlock.allocations[index].size, MetadataBlock.FS_data_descriptor);
        if (bytes_trafic != MetadataBlock.allocations[index].size)
        {
            pthread_mutex_unlock(&FS_mutex);
            return FS_ERROR;
        }
        if (MetadataBlock.cipher_mode == CIPHER_ON)
        {
            API_CP_AESOFB_encryptdecrypt(FS_data_buffer, MetadataBlock.allocations[index].size, FS_cipher_key, AES_KEY_SIZE_256, MetadataBlock.allocations[index].IV, FS_data_buffer);
        }
        int New_CRC32 = crc_32(FS_data_buffer, MetadataBlock.allocations[index].size);
        corrupted_data = (New_CRC32 == MetadataBlock.allocations[index].CRC_32_checksum) ? 0 : 1;
    }

    if (data_size <= current_size)
    { // if updated data fits in the current space of the file, we simply write the new data on the current offset
        // calculate new CRC for the data if is a CSP
        if (MetadataBlock.allocations[index].isCSP)
        {
            MetadataBlock.allocations[index].CRC_32_checksum = crc_32(data, data_size);
        }
        // cipher the new data in case is csp, and cipher mode is on:
        if (MetadataBlock.allocations[index].isCSP && MetadataBlock.cipher_mode == CIPHER_ON)
        {
            API_CP_AESOFB_encryptdecrypt(data, data_size, FS_cipher_key, AES_KEY_SIZE_256, MetadataBlock.allocations[index].IV, FS_data_buffer);
            fseek(MetadataBlock.FS_data_descriptor, current_offset + sizeof(MetadataBlock), SEEK_SET);
            bytes_trafic = fwrite(FS_data_buffer, 1, data_size, MetadataBlock.FS_data_descriptor);
        }
        else
        {
            fseek(MetadataBlock.FS_data_descriptor, current_offset + sizeof(MetadataBlock), SEEK_SET);
            bytes_trafic = fwrite(data, 1, data_size, MetadataBlock.FS_data_descriptor);
        }

        if (bytes_trafic != data_size)
        {
            pthread_mutex_unlock(&FS_mutex);
            return FS_ERROR;
        }
        // updates Metadata in case is CSP, or data is smaller than old data
        MetadataBlock.allocations[index].size = data_size;

        save_result = FS_checkdatasave(MetadataBlock.allocations[index].isCSP, SAVE_METADATA);
    }
    else
    {                                                                                // else, if we have to search for a new space in the filesystem (this fragmentates a lot the filesystem, this operation is not recomended)
        FS_quicksort(MetadataBlock.allocations, 0, MetadataBlock.num_filenames - 1); // quicksort the files, for optimal search of new space
        index = API_FS_exists_file(filename, filename_length);                       // takes the new file index after the quicksort
        int new_offset = find_space_for_data(data_size, index);

        if (new_offset == FS_MAX_SIZE_REACHED)
        { // if no more space avaiable in the file system for the updated
            pthread_mutex_unlock(&FS_mutex);
            return FS_MAX_SIZE_REACHED;
        }

        if (MetadataBlock.allocations[index].isCSP) // if CSP, zeroizes old space with Scheneier secure pattern
        {
            for (int i = 0; i < 6; i++)
            {
                fseek(MetadataBlock.FS_data_descriptor, MetadataBlock.allocations[index].offset + sizeof(MetadataBlock), SEEK_SET);
                for (int j = 0; j < MetadataBlock.allocations[index].size; FS_data_buffer[j++] = Schneier_patterns[i])
                    ;
                bytes_trafic = fwrite(FS_data_buffer, 1, MetadataBlock.allocations[index].size, MetadataBlock.FS_data_descriptor);
                if (bytes_trafic != MetadataBlock.allocations[index].size)
                {
                    pthread_mutex_unlock(&FS_mutex);
                    return FS_ERROR;
                }
            }
        }
        // write data to the new position in the filesystem
        //  if file is CSP, we update the CSP
        if (MetadataBlock.allocations[index].isCSP)
        {
            MetadataBlock.allocations[index].CRC_32_checksum = crc_32(data, data_size);
        }
        // if is csp and CIPHER mode is activated, cipher it before write:
        if (MetadataBlock.allocations[index].isCSP && MetadataBlock.cipher_mode == CIPHER_ON)
        {
            API_CP_AESOFB_encryptdecrypt(data, data_size, FS_cipher_key, AES_KEY_SIZE_256, MetadataBlock.allocations[index].IV, FS_data_buffer);
            fseek(MetadataBlock.FS_data_descriptor, new_offset + sizeof(MetadataBlock), SEEK_SET);
            bytes_trafic = fwrite(FS_data_buffer, 1, data_size, MetadataBlock.FS_data_descriptor);
        }
        else
        {
            fseek(MetadataBlock.FS_data_descriptor, new_offset + sizeof(MetadataBlock), SEEK_SET);
            bytes_trafic = fwrite(data, 1, data_size, MetadataBlock.FS_data_descriptor);
        }
        if (bytes_trafic != data_size)
        {
            pthread_mutex_unlock(&FS_mutex);
            return FS_ERROR;
        }
        // updates metadata according to the new file position in the system
        MetadataBlock.allocations[index].offset = new_offset;
        MetadataBlock.allocations[index].size = data_size;
        save_result = FS_checkdatasave(MetadataBlock.allocations[index].isCSP, SAVE_METADATA); // if the file was reallocated, we need to save the metadata
    }
    pthread_mutex_unlock(&FS_mutex);

    if (corrupted_data) // old data corrupted
        return FS_CORRUPTED_DATA;
    else if (save_result == FS_ERROR) // unsuccesfull update operation
        return FS_ERROR;
    else // succesfull update operation
        return FILESYSTEM_OK;
}

int find_space_for_data(size_t data_size, unsigned int exclude_index)
{ // auxiliar function for API_FS_update_file_data , it finds the best place for larger data

    int potential_start = 0;
    for (int i = 0; i < MetadataBlock.num_filenames; i++)
    { // looks for potential start for new file from position 0
        if (i == exclude_index)
            continue;

        int start_of_this_file = MetadataBlock.allocations[i].offset;
        int end_of_last_file = potential_start;

        if (start_of_this_file - end_of_last_file >= data_size)
        {
            return potential_start;
        }

        potential_start = MetadataBlock.allocations[i].offset + MetadataBlock.allocations[i].size;
    }
    if (MAX_FILESYSTEM_SIZE - potential_start >= data_size)
    {
        return potential_start;
    }
    return FS_MAX_SIZE_REACHED; // new size cannot fit in the current file_system
}

// Write buffer to file , does not check memory corruptions and does not updates CRC, optimized for recursive use, DO NOT USE IF FILE IS CSP
int API_FS_write_buffer_to_file(unsigned char *filename, size_t filename_length, unsigned char *buffer_in, size_t buffer_size, size_t position)
{
    if (filename == NULL || filename_length > MAX_FILENAME_LENGTH || buffer_in == NULL || buffer_size > MAX_FILE_DATA)
    {
        return FS_INCORRECT_ARGUMENT_ERROR;
    }
    if (MetadataBlock.FS_data_descriptor == NULL || MetadataBlock.filesystem_state == SYSTEM_CLOSE)
    {
        return FS_NO_FILESYSTEM_FILES;
    }
    pthread_mutex_lock(&FS_mutex);

    int index = API_FS_exists_file(filename, filename_length); // check for index of the file
    if (index == FS_NOT_EXISTANT_FILENAME)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_NOT_EXISTANT_FILENAME; // File does not exist in the file system
    }
    if (MetadataBlock.allocations[index].isCSP)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_INCORRECT_ARGUMENT_ERROR;
    }
    // Check if buffer size exceeds available space in the file
    if (position + buffer_size > MetadataBlock.allocations[index].size)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_MAX_SIZE_REACHED; // Buffer size exceeds file space
    }
    // Move the file pointer to the specified position
    fseek(MetadataBlock.FS_data_descriptor, MetadataBlock.allocations[index].offset + position + sizeof(MetadataBlock), SEEK_SET);

    // Write the buffer to the file
    size_t bytes = fwrite(buffer_in, 1, buffer_size, MetadataBlock.FS_data_descriptor);
    if (bytes != buffer_size)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_ERROR; // Error writing buffer to file
    }

    int save_result = FS_checkdatasave(NOT_CSP, NO_METADATA);
    pthread_mutex_unlock(&FS_mutex);
    if (save_result)
        return FILESYSTEM_OK; // Success
    else
        return FS_ERROR; // Error
}

// Read buffer from file , DOES NOT CHECK FOR MEMORY CORRUPTIONS, DO NOT USE IF FILE IS CSP
int API_FS_read_buffer_from_file(unsigned char *filename, size_t filename_length, unsigned char *buffer_out, size_t read_size, size_t position)
{
    if (filename == NULL || filename_length > MAX_FILENAME_LENGTH || buffer_out == NULL || read_size > MAX_FILE_DATA)
    {
        return FS_INCORRECT_ARGUMENT_ERROR;
    }
    if (MetadataBlock.FS_data_descriptor == NULL || MetadataBlock.filesystem_state == SYSTEM_CLOSE)
    {
        return FS_NO_FILESYSTEM_FILES;
    }
    pthread_mutex_lock(&FS_mutex);

    int index = API_FS_exists_file(filename, filename_length);
    if (index == FS_NOT_EXISTANT_FILENAME)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_NOT_EXISTANT_FILENAME; // File does not exist in the file system
    }
    if (MetadataBlock.allocations[index].isCSP)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_INCORRECT_ARGUMENT_ERROR;
    }
    // Check if read position and size are valid
    if (position + read_size >= MetadataBlock.allocations[index].size)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_MAX_SIZE_REACHED; // Invalid read position
    }

    // Move the file pointer to the specified position
    fseek(MetadataBlock.FS_data_descriptor, MetadataBlock.allocations[index].offset + position + sizeof(MetadataBlock), SEEK_SET);

    // Read the buffer from the file
    size_t bytes_read = fread(buffer_out, 1, read_size, MetadataBlock.FS_data_descriptor);
    if (bytes_read != (size_t)read_size)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_ERROR; // Error reading file data
    }

    int save_result = FS_checkdatasave(NOT_CSP, NO_METADATA);
    pthread_mutex_unlock(&FS_mutex);
    if (save_result)
        return FILESYSTEM_OK; // Success
    else
        return FS_ERROR;
}

int API_FS_zeroize_file_system() // funtion to zeroize every single CSP in the file_system , it
{
    int result = 1;
    size_t wrote_zeroize;
    pthread_mutex_lock(&FS_mutex);

    if (MetadataBlock.FS_data_descriptor == NULL || MetadataBlock.filesystem_state == SYSTEM_CLOSE)
    {
        pthread_mutex_unlock(&FS_mutex);
        return FS_NO_FILESYSTEM_FILES;
    }
    for (int i = 0; i < MetadataBlock.num_filenames; i++)
    {
        if (MetadataBlock.allocations[i].isCSP)
        {
            wrote_zeroize = 0;
            for (int j = 0; j < 6; j++)
            {
                fseek(MetadataBlock.FS_data_descriptor, MetadataBlock.allocations[i].offset + sizeof(MetadataBlock), SEEK_SET);
                for (int k = 0; k < MetadataBlock.allocations[i].size; FS_data_buffer[k++] = Schneier_patterns[j])
                    ;
                wrote_zeroize += fwrite(FS_data_buffer, MetadataBlock.allocations[i].size, 1, MetadataBlock.FS_data_descriptor);
            }
            if (wrote_zeroize != 6)
            {
                result = 0;
            }
        }
    }
    fflush(MetadataBlock.FS_data_descriptor);
    pthread_mutex_unlock(&FS_mutex);
    if (result)
    {
        return FILESYSTEM_OK;
    }
    else
    {
        return FS_ERROR;
    }
}

void API_FS_Close_filesystem()
{ // easy functions to force close the file_system, ignoring other threads
    MetadataBlock.filesystem_state = SYSTEM_CLOSE;
    FS_saveall_metadatablock();
    fclose(MetadataBlock.FS_data_descriptor);
}

//
//                             TESTING FUNCTIONS, ONLY FOR UNITARY TESTING
//

void print_bytes(unsigned char *filename, size_t filename_length, int num_bytes)
{
    int index = API_FS_exists_file(filename, filename_length);
    printf("el index es : %d\n", index);
    if (index != -1)
    {
        int data_length;
        unsigned char *data;
        API_FS_read_file_data(filename, filename_length, &data, &data_length);

        if (data != NULL)
        {
            printf("%d bytes of file '%s' (ASCII representation):\n", num_bytes, filename);

            int bytes_to_print = data_length < num_bytes ? data_length : num_bytes;
            for (int i = 0; i < bytes_to_print; i++)
            {
                printf("%c", isprint(data[i]) ? data[i] : '.');
            }
            printf("\n");
        }
        else
        {
            printf("Error reading file data.\n");
        }
    }
    else
    {
        printf("File not found.\n");
    }
}

void print_files_content()
{
    printf("File System Contents:\n");

    for (int i = 0; i < MetadataBlock.num_filenames; i++)
    {
        print_bytes(MetadataBlock.allocations[i].filename, MetadataBlock.allocations[i].filename_length, MetadataBlock.allocations->size);
    }
}

void print_files()
{
    printf("File System Contents:\n\n");

    for (int i = 0; i < MetadataBlock.num_filenames; i++)
    {
        for (int j = 0; j < MetadataBlock.allocations[i].filename_length; j++)
        {
            putchar(MetadataBlock.allocations[i].filename[j]);
        }
        printf(" | Offset: %d | Size: %ld bytes | CRC : %u\n", MetadataBlock.allocations[i].offset, MetadataBlock.allocations[i].size, MetadataBlock.allocations[i].CRC_32_checksum);
    }
    printf("\n");
}
