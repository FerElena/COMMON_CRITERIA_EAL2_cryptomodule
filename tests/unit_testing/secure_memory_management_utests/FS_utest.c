/**
 * @file FS_utest.c
 * @brief Unitary testing the file system functionality, it exclude the testing of the functionality that corresponds to the SO (example, fopen returns NULL on wb+ mode)
 *for see intermediate file system state, you can use tetsing functions printfiles() and print_files_content()
 */

////////////////////////////////////////////  TESTING DATA  //////////////////////////////////////////////////////////////////

// Metadata block size : 1440536

#include "FS_utest.h"

#define METADATA_SIZE 1440536

#define CIPHER_MODE 1

#define file_system_rpath "tests/unit_testing/filesystem_unitarytest_data" //testing filesystem path 

unsigned char data[] = "this is not a random generated test, I wrote it because idk what to write for the test,thisisto 100";
unsigned char newdata[MAX_FILE_DATA] = {1, 2, 3, 3};
unsigned char buffercorrompe[] = "este texto está corrompiendo el fichero";

unsigned char *filename1 = "filename1";
unsigned char *filename2 = "filename2";
unsigned char *filename3 = "filename3";
unsigned char *filename4 = "filename4";
unsigned char *filename5 = "filename5";
unsigned char *filename6 = "filename6";
unsigned char *filename7 = "filename7";
unsigned char *filename8 = "filename8";
unsigned char *filename9 = "filename9";
unsigned char *filename10 = "filename10";
unsigned char *filename11 = "filename11";
unsigned char *filename12 = "filename12";
unsigned char *filename13 = "filename13";
unsigned char *filename14 = "filename14";
unsigned char *filename15 = "filename15";
unsigned char *filename16 = "filename16";
unsigned char *filename17 = "filename17";
unsigned char *filename18 = "filename18";
unsigned char *filename19 = "filename19";
unsigned char *filename20 = "filename20";
unsigned char *filename21 = "filename21";
unsigned char *filename22 = "filename22";
unsigned char *filename23 = "filename23";
unsigned char *filename24 = "filename24";
unsigned char *filename25 = "filename25";
unsigned char *filename26 = "filename26";
unsigned char *filename27 = "filename27";
unsigned char *filename28 = "filename28";
unsigned char *filename29 = "filename29";

//testing key
uint8_t key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

////////////////////////////////////////////  TESTING SET  //////////////////////////////////////////////////////////////////


START_TEST(test_API_FS_initiate_file_system)
{
    //test for incorrect argument input parameters
    ck_assert_int_eq(API_FS_initiate_file_system(MODE_INIT, NULL, strlen(file_system_rpath)),FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_initiate_file_system(MODE_INIT, file_system_rpath, 513),FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_initiate_file_system(420, file_system_rpath, strlen(file_system_rpath)),FS_INCORRECT_MODE);
    
    //testing if we can open correctly the file_system
    ck_assert_int_eq(API_FS_initiate_file_system(MODE_INIT, file_system_rpath, strlen(file_system_rpath)),FILESYSTEM_OK);
    FILE *f = fopen(file_system_rpath,"r");
    ck_assert_ptr_nonnull(f);

    //setup choosen cipher
    API_FS_setup_cipher(CIPHER_MODE, key);

    // testing if file_system size is according to MAX_FILESYSTEM_SIZE
    f = fopen(file_system_rpath, "rb");
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    ck_assert_int_eq(size,MAX_FILESYSTEM_SIZE + METADATA_SIZE);

    // create a file to test that persistence of data is correct after a MODE_LOAD
    ck_assert_int_eq(API_FS_create_file_data(filename1, strlen(filename1), data, sizeof(data), NOT_CSP),FILESYSTEM_OK);
    API_FS_Close_filesystem();
    ck_assert_int_eq(API_FS_initiate_file_system(MODE_LOAD, file_system_rpath, strlen(file_system_rpath)),FILESYSTEM_OK);

    //check if file still exists
    ck_assert_int_ne(API_FS_exists_file(filename1, strlen(filename1)),FS_NOT_EXISTANT_FILENAME);
    
    //close filesystem
    API_FS_Close_filesystem();
    remove(file_system_rpath);

}
END_TEST

START_TEST(test_API_FS_exists_file)
{
    //open a new filesystem
    ck_assert_int_eq(API_FS_initiate_file_system(MODE_INIT, file_system_rpath, strlen(file_system_rpath)),FILESYSTEM_OK);
    //setup choosen cipher
    API_FS_setup_cipher(CIPHER_MODE, key);

    //try find a non existing file
    ck_assert_int_eq(API_FS_exists_file(filename1, strlen(filename1)),FS_NOT_EXISTANT_FILENAME);

    // create a file 
    ck_assert_int_eq(API_FS_create_file_data(filename1, strlen(filename1), data, sizeof(data), NOT_CSP),FILESYSTEM_OK);

    //test find an existing file
    ck_assert_int_ne(API_FS_exists_file(filename1, strlen(filename1)),FS_NOT_EXISTANT_FILENAME);

    //close filesystem
    API_FS_Close_filesystem();
    remove(file_system_rpath);
}
END_TEST

START_TEST(test_API_FS_create_file_data)
{
    //open a new filesystem
    ck_assert_int_eq(API_FS_initiate_file_system(MODE_INIT, file_system_rpath, strlen(file_system_rpath)),FILESYSTEM_OK);
    //setup choosen cipher
    API_FS_setup_cipher(CIPHER_MODE, key);

    //testing incorrect parameters
    ck_assert_int_eq(API_FS_create_file_data(filename7, strlen(filename7), data, sizeof(data), 2),FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_create_file_data(filename7, strlen(filename7), NULL, sizeof(data), 1),FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_create_file_data(NULL, strlen(filename7), data, sizeof(data), 1),FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_create_file_data(filename7, strlen(filename7), data, MAX_FILE_DATA + 1, 1),FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_create_file_data(filename7, MAX_FILENAME_LENGTH+1, data, sizeof(data), 1),FS_INCORRECT_ARGUMENT_ERROR);

    // testing inserting files ok
    unsigned char *files[] = {filename2, filename3, filename4, filename5, filename6};
    for (int i = 0; i < 5; i++)
    {
        ck_assert_int_eq(API_FS_create_file_data(files[i], strlen(files[i]), data, sizeof(data), IS_CSP),FILESYSTEM_OK);
    }

    // testing triying to create an already existing file
    ck_assert_int_eq(API_FS_create_file_data(filename5, strlen(filename5), data, sizeof(data), IS_CSP) , FS_FILENAME_ALREADYEXIST_ERROR);

    // testing if in case no more filesystem space, the file does not get inserted:

    API_FS_create_file_data(filename8, strlen(filename8), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename9, strlen(filename9), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename10, strlen(filename10), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename11, strlen(filename11), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename12, strlen(filename12), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename13, strlen(filename13), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename14, strlen(filename14), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename15, strlen(filename15), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename16, strlen(filename16), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename17, strlen(filename17), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename18, strlen(filename18), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename19, strlen(filename19), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename20, strlen(filename20), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename21, strlen(filename21), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename22, strlen(filename22), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename23, strlen(filename23), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename24, strlen(filename24), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename25, strlen(filename25), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename26, strlen(filename26), newdata, sizeof(newdata), IS_CSP);
    API_FS_create_file_data(filename27, strlen(filename27), newdata, sizeof(newdata), IS_CSP);

    ck_assert_int_eq(API_FS_create_file_data(filename28, strlen(filename28), newdata, sizeof(newdata), IS_CSP) , FS_MAX_SIZE_REACHED);

    //close filesystem
    API_FS_Close_filesystem();
    remove(file_system_rpath);
}
END_TEST

START_TEST(test_API_FS_delete_file)
{
    //open a new filesystem
    ck_assert_int_eq(API_FS_initiate_file_system(MODE_INIT, file_system_rpath, strlen(file_system_rpath)),FILESYSTEM_OK);
    //setup choosen cipher
    API_FS_setup_cipher(CIPHER_MODE, key);

    // testing correct parameter checking
    ck_assert_int_eq(API_FS_delete_file(NULL, 5) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_delete_file(filename2, MAX_FILENAME_LENGTH + 1) , FS_INCORRECT_ARGUMENT_ERROR);

    // testing triying to delete a non existing file
    ck_assert_int_eq(API_FS_delete_file(filename29, strlen(filename29)) , FS_NOT_EXISTANT_FILENAME);

    //inserting some files for testing
    unsigned char *files[] = {filename2, filename3, filename4, filename5, filename6};
    for (int i = 0; i < 5; i++)
    {
        ck_assert_int_eq(API_FS_create_file_data(files[i], strlen(files[i]), data, sizeof(data), IS_CSP),FILESYSTEM_OK);
    }
    //testing correct deletion of a file
    ck_assert_int_eq(API_FS_delete_file(filename6, strlen(filename6)) , FILESYSTEM_OK);

    // writing of file2 to test corruption detection before delete
    FILE *fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE + 10, SEEK_SET); // size of metadata block + offset of file2
    fwrite(buffercorrompe, sizeof(buffercorrompe), 1, fd);
    fclose(fd); // secure writing in the file

    ck_assert_int_eq(API_FS_delete_file(filename2, strlen(filename2)) , FS_CORRUPTED_DATA);

    // testing if zeroization was correct after delete the file:
    unsigned char delete_buffer_test[100];
    fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE , SEEK_SET); // size of metadata block + offset of file2
    fread(delete_buffer_test, 100, 1, fd);
    fclose(fd);

    for (int i = 0; i < sizeof(delete_buffer_test); i++)
    {
        ck_assert_int_eq(delete_buffer_test[i],0x55);
    }

    //close filesystem
    API_FS_Close_filesystem();
    remove(file_system_rpath);
}
END_TEST

START_TEST(test_API_FS_read_file_data)
{
    int test_read1;
    unsigned char *test_read2;

    //open a new filesystem
    ck_assert_int_eq(API_FS_initiate_file_system(MODE_INIT, file_system_rpath, strlen(file_system_rpath)),FILESYSTEM_OK);
    //setup choosen cipher
    API_FS_setup_cipher(CIPHER_MODE, key);

    // testing correct parameter checking
    ck_assert_int_eq(API_FS_read_file_data(NULL, strlen(filename29), &test_read2, &test_read1) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_read_file_data(filename29, MAX_FILENAME_LENGTH + 1, &test_read2, &test_read1) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_read_file_data(filename29, strlen(filename29), NULL, &test_read1) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_read_file_data(filename29, strlen(filename29), &test_read2, NULL) , FS_INCORRECT_ARGUMENT_ERROR);

    // testing correct reading of an existing file :
    unsigned char *filename29_data = "este texto será utilizado para testear la función API_FS_read_file_data";
    int len_data_filename29 = strlen(filename29_data);
    unsigned char *read_pointer_filename29;
    int New_len_data_filename29;

    ck_assert_int_eq(API_FS_create_file_data(filename29, strlen(filename29), filename29_data, len_data_filename29, IS_CSP),FILESYSTEM_OK);
    int value_readfile_test = API_FS_read_file_data(filename29, strlen(filename29), &read_pointer_filename29, &New_len_data_filename29);

    ck_assert_int_eq(value_readfile_test,FILESYSTEM_OK);
    ck_assert_int_eq(len_data_filename29,New_len_data_filename29);
    ck_assert_mem_eq(filename29_data,read_pointer_filename29,len_data_filename29);

    // testing triying to read a non existing filename
    ck_assert_int_eq(API_FS_read_file_data(filename3, strlen(filename3), &test_read2, &test_read1) , FS_NOT_EXISTANT_FILENAME);

    // testing detection of data corruption
    FILE *fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE , SEEK_SET); // size of metadata block + current offset of file29
    fwrite(buffercorrompe, sizeof(buffercorrompe), 1, fd);
    fclose(fd); // secure writing in the file
    ck_assert_int_eq(API_FS_read_file_data(filename29, strlen(filename29), &read_pointer_filename29, &New_len_data_filename29) , FS_CORRUPTED_DATA);

    //close filesystem
    API_FS_Close_filesystem();
    remove(file_system_rpath);
}
END_TEST

START_TEST(test_API_FS_rename_file)
{
    //open a new filesystem
    ck_assert_int_eq(API_FS_initiate_file_system(MODE_INIT, file_system_rpath, strlen(file_system_rpath)),FILESYSTEM_OK);
    //setup choosen cipher
    API_FS_setup_cipher(CIPHER_MODE, key);

    // testing correct parameter checking
    ck_assert_int_eq(API_FS_rename_file(NULL, strlen(filename29), filename28, strlen(filename28)) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_rename_file(filename29, MAX_FILENAME_LENGTH + 1, filename28, strlen(filename28)) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_rename_file(filename29, strlen(filename29), NULL, strlen(filename28)) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_rename_file(filename29, strlen(filename29), filename28, MAX_FILENAME_LENGTH + 1) , FS_INCORRECT_ARGUMENT_ERROR);

    //create file for testing purposes
    API_FS_create_file_data(filename1, strlen(filename1), data,strlen(data), IS_CSP);

    //testing correct rename
    ck_assert_int_eq(API_FS_rename_file(filename1, strlen(filename1), filename3, strlen(filename3)) , FILESYSTEM_OK);

    // testing triying to rename a non existing file
    ck_assert_int_eq(API_FS_rename_file(filename2, strlen(filename2), filename4, strlen(filename4)) , FS_NOT_EXISTANT_FILENAME);

    //close filesystem
    API_FS_Close_filesystem();
    remove(file_system_rpath);
}
END_TEST

START_TEST(test_API_FS_update_file_data)
{
    unsigned char data_more[] = "this is not a random generated test, I wrote it because idk what to write for the test,this data have more than 100 characters";
    unsigned char data_less[] = "this is not a random generated test, this data have less than 100 characters";

    //open a new filesystem
    ck_assert_int_eq(API_FS_initiate_file_system(MODE_INIT, file_system_rpath, strlen(file_system_rpath)),FILESYSTEM_OK);
    //setup choosen cipher
    API_FS_setup_cipher(CIPHER_MODE, key);

    // testing correct parameter checking
    ck_assert_int_eq(API_FS_update_file_data(NULL, strlen(filename4), data_more, strlen(data_more)) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_update_file_data(filename4, MAX_FILENAME_LENGTH + 1, data_more, strlen(data_more)) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_update_file_data(filename4, strlen(filename4), NULL, strlen(data_more)) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_update_file_data(filename4, strlen(filename4), data_more, MAX_FILE_DATA + 1) , FS_INCORRECT_ARGUMENT_ERROR);

    // testing triying to update a non existant file
    ck_assert_int_eq(API_FS_update_file_data(filename29, strlen(filename29), data_more, strlen(data_more)) , FS_NOT_EXISTANT_FILENAME);

    //create file for testing purposes
    API_FS_create_file_data(filename1, strlen(filename1), data,sizeof(data), IS_CSP);
    API_FS_create_file_data(filename2, strlen(filename2), data,sizeof(data), IS_CSP);
    API_FS_create_file_data(filename3, strlen(filename3), data,sizeof(data), IS_CSP);

    //testing correct update if size <= actual file size
    ck_assert_int_eq(API_FS_update_file_data(filename2, strlen(filename2), data_less, sizeof(data_less)) , FILESYSTEM_OK);

    // testing correct update if size > actual file size
    ck_assert_int_eq(API_FS_update_file_data(filename2, strlen(filename2), data_more, sizeof(data_more)) , FILESYSTEM_OK);

    // testing if old data is correctly zeroized
    unsigned char delete_buffer_test2[76];
    FILE *fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE + 100, SEEK_SET); // size of metadata block + current offset of filename4
    fread(delete_buffer_test2, 76, 1, fd);
    fclose(fd);
    for(int i = 0 ; i < sizeof(data_less)-1 ; i++){
        ck_assert_int_eq(delete_buffer_test2[i],0x55);
    }
    // testing data corruption before update :
    fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE , SEEK_SET); // size of metadata block 
    fwrite(buffercorrompe, sizeof(buffercorrompe), 1, fd);
    fclose(fd); // secure writing in the file
    ck_assert_int_eq(API_FS_update_file_data(filename1, strlen(filename1), buffercorrompe, sizeof(buffercorrompe)) , FS_CORRUPTED_DATA);

    //close filesystem
    API_FS_Close_filesystem();
    remove(file_system_rpath);
}
END_TEST

START_TEST(test_API_FS_write_buffer_to_file)
{
    //open a new filesystem
    ck_assert_int_eq(API_FS_initiate_file_system(MODE_INIT, file_system_rpath, strlen(file_system_rpath)),FILESYSTEM_OK);
    //setup choosen cipher
    API_FS_setup_cipher(CIPHER_MODE, key);
    unsigned char *writeread_test_buffer = "this buffer is going to be utilized to test the write and red from a file functions, I hope it works";
    unsigned char *write_buffer_test = "writing this in a file!";

    //create file for testing purposes
    API_FS_create_file_data(filename1, strlen(filename1), data,sizeof(data), NOT_CSP);
    API_FS_create_file_data(filename2, strlen(filename2), data,sizeof(data), IS_CSP);
    API_FS_create_file_data(filename3, strlen(filename3), data,sizeof(data), IS_CSP);

    // testing correct parameter checking
    ck_assert_int_eq(API_FS_write_buffer_to_file(NULL, strlen(filename1), write_buffer_test, strlen(write_buffer_test), 10) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_write_buffer_to_file(filename1, MAX_FILENAME_LENGTH + 1, write_buffer_test, strlen(write_buffer_test), 10), FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_write_buffer_to_file(filename1, strlen(filename1), NULL, strlen(write_buffer_test), 10) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_write_buffer_to_file(filename1, strlen(filename1), write_buffer_test, MAX_FILE_DATA + 1, 10) , FS_INCORRECT_ARGUMENT_ERROR);
    
    // testing you cannot write on a non-existing file
    ck_assert_int_eq(API_FS_write_buffer_to_file(filename4, strlen(filename4), write_buffer_test, strlen(write_buffer_test), 10) , FS_NOT_EXISTANT_FILENAME);

    // testing you cannot write more size than the size of the current size of the file
    ck_assert_int_eq(API_FS_write_buffer_to_file(filename1, strlen(filename1), writeread_test_buffer, strlen(writeread_test_buffer), 10) , FS_MAX_SIZE_REACHED);

    // testing correct buffer write on a file :
    ck_assert_int_eq(API_FS_write_buffer_to_file(filename1, strlen(filename1), write_buffer_test, strlen(write_buffer_test), 12) , FILESYSTEM_OK);
    unsigned char *write_buffer_result = "this is not writing this in a file!, I wrote it because idk what to write for the test,thisisto 100";

    unsigned char *write_buffer_test2;
    int length_write_buffer;
    API_FS_read_file_data(filename1, strlen(filename1), &write_buffer_test2, &length_write_buffer);
    ck_assert_mem_eq(write_buffer_test2,write_buffer_result,length_write_buffer);

    //close filesystem
    API_FS_Close_filesystem();
    remove(file_system_rpath);
}
END_TEST

START_TEST(test_API_FS_read_buffer_from_file)
{
    //open a new filesystem
    ck_assert_int_eq(API_FS_initiate_file_system(MODE_INIT, file_system_rpath, strlen(file_system_rpath)),FILESYSTEM_OK);
    //setup choosen cipher
    API_FS_setup_cipher(CIPHER_MODE, key);
    //create file for testing purposes
    API_FS_create_file_data(filename1, strlen(filename1), data,sizeof(data), NOT_CSP);
    API_FS_create_file_data(filename2, strlen(filename2), data,sizeof(data), IS_CSP);
    API_FS_create_file_data(filename3, strlen(filename3), data,sizeof(data), IS_CSP);
    unsigned char read_pointer_test[2000000];
    unsigned char *writeread_test_buffer = "this buffer is going to be utilized to test the write and red from a file functions, I hope it works";
    unsigned char *write_buffer_test = "writing this in a file!";

    // testing correct parameter checking
    ck_assert_int_eq(API_FS_read_buffer_from_file(NULL, strlen(filename1), read_pointer_test, strlen(write_buffer_test), 12) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_read_buffer_from_file(filename1, MAX_FILENAME_LENGTH + 1, read_pointer_test, strlen(write_buffer_test), 12) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_read_buffer_from_file(filename1, strlen(filename1), NULL, strlen(write_buffer_test), 12) , FS_INCORRECT_ARGUMENT_ERROR);
    ck_assert_int_eq(API_FS_read_buffer_from_file(filename1, strlen(filename1), read_pointer_test, MAX_FILE_DATA + 1, 12) , FS_INCORRECT_ARGUMENT_ERROR);

    // testing you cannot read on a non-existing file
    ck_assert_int_eq(API_FS_read_buffer_from_file(filename4, strlen(filename4), read_pointer_test, strlen(write_buffer_test), 12) , FS_NOT_EXISTANT_FILENAME);

    // testing you cannot read more size than the current size of the file
    ck_assert_int_eq(API_FS_read_buffer_from_file(filename1, strlen(filename1), read_pointer_test, strlen(writeread_test_buffer), 10) , FS_MAX_SIZE_REACHED);

    // testing correct buffer reading on a file:
    unsigned char *test_read_string = "this is not a random generated test";
    ck_assert_int_eq(API_FS_read_buffer_from_file(filename1, strlen(filename1), read_pointer_test, strlen(test_read_string), 0) , FILESYSTEM_OK);
    ck_assert_mem_eq(read_pointer_test,test_read_string,strlen(test_read_string));

    //close filesystem
    API_FS_Close_filesystem();
    remove(file_system_rpath);
}
END_TEST

START_TEST(test_API_FS_zeroize_file_system)
{
    //open a new filesystem
    ck_assert_int_eq(API_FS_initiate_file_system(MODE_INIT, file_system_rpath, strlen(file_system_rpath)),FILESYSTEM_OK);
    //setup choosen cipher
    API_FS_setup_cipher(CIPHER_MODE, key);
    //create file for testing purposes
    API_FS_create_file_data(filename1, strlen(filename1), data,sizeof(data), IS_CSP);
    API_FS_create_file_data(filename2, strlen(filename2), data,sizeof(data), IS_CSP);
    API_FS_create_file_data(filename3, strlen(filename3), data,sizeof(data), IS_CSP);

    //testing correct zeroization
    ck_assert_int_eq(API_FS_zeroize_file_system() , FILESYSTEM_OK);

    unsigned char delete_buffer_test3[MAX_FILE_DATA];
    FILE *fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE, SEEK_SET); // file 1 offset
    fread(delete_buffer_test3, 100, 1, fd);
    fclose(fd);
    for(int i = 0 ; i < 100 ; i++)
        ck_assert_int_eq(delete_buffer_test3[i],0x55);
    
    fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE + 100, SEEK_SET); // file 2 offset
    fread(delete_buffer_test3, 100, 1, fd);
    fclose(fd);
    for(int i = 0 ; i < 100 ; i++)
        ck_assert_int_eq(delete_buffer_test3[i],0x55);

    fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE + 200, SEEK_SET); // file 3 offset
    fread(delete_buffer_test3, 100, 1, fd);
    fclose(fd);
    for(int i = 0 ; i < 100 ; i++)
        ck_assert_int_eq(delete_buffer_test3[i],0x55);

    //close filesystem
    API_FS_Close_filesystem();
    remove(file_system_rpath);
}
END_TEST


// test_suite
Suite *FS_suite(void){
    Suite *s;
    TCase *tc_core;

    s = suite_create("File_System_utests");
    tc_core = tcase_create("Core_FS_utest");

    // adding test cases
    tcase_add_test(tc_core, test_API_FS_initiate_file_system);
    tcase_add_test(tc_core, test_API_FS_exists_file);
    tcase_add_test(tc_core, test_API_FS_create_file_data);
    tcase_add_test(tc_core, test_API_FS_delete_file);
    tcase_add_test(tc_core, test_API_FS_read_file_data);
    tcase_add_test(tc_core, test_API_FS_rename_file);
    tcase_add_test(tc_core, test_API_FS_update_file_data);
    tcase_add_test(tc_core, test_API_FS_write_buffer_to_file);
    tcase_add_test(tc_core, test_API_FS_read_buffer_from_file);
    tcase_add_test(tc_core, test_API_FS_zeroize_file_system);

    suite_add_tcase(s, tc_core);

    return s;
}

