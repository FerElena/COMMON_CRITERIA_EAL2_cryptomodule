
// main for unitary testing the file system functionality, it exclude the testing of the functionality that corresponds to the SO (example, fopen returns NULL on wb+ mode)
// for see intermediate file system state, you can use tetsing functions printfiles() and print_files_content()

// gcc testing_file_system.c file_system.c ../crypto/CRC_Galileo.c -o pruebas_filesystem     // compiling comand

// tamaño bloque metadatos : 1440536
#define METADATA_SIZE 1440536

#define CIPHER_MODE 1

#include "testing_file_system.h"

void print_test_Result(uint8_t result[], unsigned char test_name[])
{ // funtions for printing test fails in case of test failure
    for (int i = 0; i < 50; i++)
    {
        if (result[i])
        {
            printf("\x1B[31m"
                   "test number %d in the testing of funtion %s have failed"
                   "\x1B[0m"
                   "\n",
                   i, test_name);
            result[i]--;
        }
    }
}

void FS_testing()
{
    printf("\x1B[34m"
           "                           FILESYSTEM_UNITARYTESTING_BEGIN"
           "\x1B[0m"
           "\n");

    uint8_t failed_test[50] = {0}; // array for check in which test it fails in case testing fails
    uint8_t correct_test = 1;      // we suppose all tests are correct, we put this variable to 0 in other case
    int value_returned;            // value to check the return values of functions
    int finalvalue = 1;            // final value for passed tests or no
    FILE *f;                       // file descriptor to externally check things inside file_system

    printf("\x1B[34m"
           "\nAPI_FS_initiate_file_system TESTING "
           "\x1B[0m"
           "\n");
    // testing MODE_INIT

    // testing error if wrong parameters
    if (API_FS_initiate_file_system(MODE_INIT, NULL, strlen(file_system_rpath)) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[0]++;
        correct_test = 0;
    }
    if (API_FS_initiate_file_system(MODE_INIT, file_system_rpath, 513) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[1]++;
        correct_test = 0;
    }

    // testing if we can open correctly the file_system

    value_returned = API_FS_initiate_file_system(MODE_INIT, file_system_rpath, strlen(file_system_rpath));
    if (value_returned != FILESYSTEM_OK)
    {
        failed_test[3]++;
        correct_test = 0;
    }

    uint8_t key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    API_FS_setup_cipher(CIPHER_MODE, key);
    // testing if file_system size is according to MAX_FILESYSTEM_SIZE
    f = fopen(file_system_rpath, "rb");
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);

    if (size != ((40 * 1024 * 1024) + METADATA_SIZE))
    { // size of metadatablock + sizeof data
        failed_test[4]++;
        correct_test = 0;
    }

    // testing MODE_LOAD

    // create a file to test that persistence of data is correct after a MODE_LOAD
    unsigned char data[] = "this is not a random generated test, I wrote it because idk what to write for the test,thisisto 100";
    unsigned char *filename1 = "filename1";

    API_FS_create_file_data(filename1, strlen(filename1), data, sizeof(data), NOT_CSP);

    print_files();

    API_FS_Close_filesystem();

    // LOADS again the file_system overwriting the data in the Metadata structure
    value_returned = API_FS_initiate_file_system(MODE_LOAD, file_system_rpath, strlen(file_system_rpath));
    if (value_returned != FILESYSTEM_OK)
    {
        failed_test[5]++;
        correct_test = 0;
    }
    // checks file still correctly exists
    print_files();
    if (API_FS_exists_file(filename1, strlen(filename1)) < 0)
    {
        failed_test[6]++;
        correct_test = 0;
    }
    // checks what function returns if called with incorrect mode

#define NOT_CORRECT_MODE 999

    value_returned = API_FS_initiate_file_system(NOT_CORRECT_MODE, file_system_rpath, strlen(file_system_rpath));
    if (value_returned != FS_INCORRECT_MODE)
    {
        failed_test[7]++;
        correct_test = 0;
    }

    if (correct_test)
    {
        printf("\x1B[32m"
               "tests of API_FS_initiate_file_system passed correctly"
               "\x1B[0m"
               "\n");
    }
    else
    {
        print_test_Result(failed_test, "API_FS_initiate_file_system");
        correct_test = 1;
        finalvalue = 0;
    }

    printf("\x1B[34m"
           "\nAPI_FS_exists_file TESTING "
           "\x1B[0m"
           "\n");

    if (API_FS_exists_file(filename1, strlen(filename1)) < 0)
    {
        failed_test[0]++;
        correct_test = 0;
    }

    if (API_FS_exists_file("testing_file2", strlen(filename1) + 1) != FS_NOT_EXISTANT_FILENAME)
    {
        failed_test[1]++;
        correct_test = 0;
    }

    if (correct_test)
    {
        printf("\x1B[32m"
               "tests of API_FS_exists_file passed correctly"
               "\x1B[0m"
               "\n");
    }
    else
    {
        print_test_Result(failed_test, "API_FS_exists_file");
        correct_test = 1;
        finalvalue = 0;
    }

    printf("\x1B[34m"
           "\nAPI_FS_create_file_data TESTING "
           "\x1B[0m"
           "\n");

    // testing inserting files ok

    unsigned char *filename2 = "filename2";
    unsigned char *filename3 = "filename3";
    unsigned char *filename4 = "filename4";
    unsigned char *filename5 = "filename5";
    unsigned char *filename6 = "filename6";

    unsigned char *files[] = {filename2, filename3, filename4, filename5, filename6};

    for (int i = 0; i < 5; i++)
    {
        if (API_FS_create_file_data(files[i], strlen(files[i]), data, sizeof(data), IS_CSP) != FILESYSTEM_OK)
        {
            failed_test[0]++;
            correct_test = 0;
        }
    }

    // testing wrong parameters input

    unsigned char *filename7 = "filename7";

    if (API_FS_create_file_data(filename7, strlen(filename7), data, sizeof(data), 2) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[1]++;
        correct_test = 0;
    }
    if (API_FS_create_file_data(filename7, strlen(filename7), NULL, sizeof(data), 2) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[2]++;
        correct_test = 0;
    }
    if (API_FS_create_file_data(NULL, strlen(filename7), data, sizeof(data), 2) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[3]++;
        correct_test = 0;
    }
    if (API_FS_create_file_data(filename7, strlen(filename7), data, MAX_FILE_DATA + 1, 2) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[4]++;
        correct_test = 0;
    }
    if (API_FS_create_file_data(filename7, MAX_FILENAME_LENGTH, data, sizeof(data), 2) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[5]++;
        correct_test = 0;
    }

    // testing triying to create an already existing file
    if (API_FS_create_file_data(filename5, strlen(filename5), data, sizeof(data), IS_CSP) != FS_FILENAME_ALREADYEXIST_ERROR)
    {
        failed_test[6]++;
        correct_test = 0;
    }

    // testing if file is inserted if there is a gap between 2 files:

    API_FS_delete_file(filename3, strlen(filename3));
    API_FS_create_file_data(filename7, strlen(filename7), data, sizeof(data) - 20, NOT_CSP);
    printf("\ncheck if file7 is between file2 and file4 ! \n\n");
    print_files();

    // testing if in case no more filesystem space, the file does not get inserted:

    unsigned char newdata[MAX_FILE_DATA] = {1, 2, 3, 3};

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

    if (API_FS_create_file_data(filename28, strlen(filename28), newdata, sizeof(newdata), IS_CSP) != FS_MAX_SIZE_REACHED)
    {
        failed_test[7]++;
        correct_test = 0;
    }

    if (correct_test)
    {
        printf("\x1B[32m"
               "tests of API_FS_create_file_data passed correctly"
               "\x1B[0m"
               "\n");
    }
    else
    {
        print_test_Result(failed_test, "API_FS_create_file_data");
        correct_test = 1;
        finalvalue = 0;
    }

    printf("\x1B[34m"
           "\nAPI_FS_delete_file TESTING "
           "\x1B[0m"
           "\n");

    // testing correct parameter checking

    if (API_FS_delete_file(NULL, 5) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[0]++;
        correct_test = 0;
    }
    if (API_FS_delete_file(filename2, MAX_FILENAME_LENGTH + 1) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[1]++;
        correct_test = 0;
    }
    // testing triying to delete a non existing file

    if (API_FS_delete_file(filename29, strlen(filename29)) != FS_NOT_EXISTANT_FILENAME)
    {
        failed_test[2]++;
        correct_test = 0;
    }
    // testing correct deletion of existing filename
    if (API_FS_delete_file(filename8, strlen(filename8)) != FILESYSTEM_OK)
    {
        failed_test[3]++;
        correct_test = 0;
    }

    // writing of file2 to test corruption detection before delete
    FILE *fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE + 100, SEEK_SET); // size of metadata block + offset of file2
    unsigned char buffercorrompe[] = "este texto está corrompiendo el fichero";
    fwrite(buffercorrompe, sizeof(buffercorrompe), 1, fd);
    fclose(fd); // secure writing in the file

    if (API_FS_delete_file(filename2, strlen(filename2)) != FS_CORRUPTED_DATA)
    {
        failed_test[4]++;
        correct_test = 0;
    }

    // testing if zeroization was correct after delete the file:
    unsigned char delete_buffer_test[100];
    fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE + 100, SEEK_SET); // size of metadata block + offset of file2
    fread(delete_buffer_test, 100, 1, fd);
    fclose(fd);

    for (int i = 0; i < sizeof(delete_buffer_test); i++)
    {
        if (delete_buffer_test[i] != 0x55)
        {
            failed_test[5]++;
            printf("%02x ", delete_buffer_test[i]);
            correct_test = 0;
            // break;
        }
    }
    printf("\n");

    if (correct_test)
    {
        printf("\x1B[32m"
               "tests of API_FS_delete_file passed correctly"
               "\x1B[0m"
               "\n");
    }
    else
    {
        print_test_Result(failed_test, "API_FS_delete_file");
        correct_test = 1;
        finalvalue = 0;
    }

    printf("\x1B[34m"
           "\nAPI_FS_read_file_data TESTING "
           "\x1B[0m"
           "\n");

    // testing correct parameter checking
    int test_read1;
    unsigned char *test_read2;

    if (API_FS_read_file_data(NULL, strlen(filename29), &test_read2, &test_read1) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[0]++;
        correct_test = 0;
    }
    if (API_FS_read_file_data(filename29, MAX_FILENAME_LENGTH + 1, &test_read2, &test_read1) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[1]++;
        correct_test = 0;
    }
    if (API_FS_read_file_data(filename29, strlen(filename29), NULL, &test_read1) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[2]++;
        correct_test = 0;
    }
    if (API_FS_read_file_data(filename29, strlen(filename29), &test_read2, NULL) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[3]++;
        correct_test = 0;
    }

    // testing correct reading of an existing file :

    unsigned char *filename29_data = "este texto será utilizado para testear la función API_FS_read_file_data";
    int len_data_filename29 = strlen(filename29_data);

    API_FS_create_file_data(filename29, strlen(filename29), filename29_data, len_data_filename29, IS_CSP);

    unsigned char *read_pointer_filename29;
    int New_len_data_filename29;
    int value_readfile_test;

    value_readfile_test = API_FS_read_file_data(filename29, strlen(filename29), &read_pointer_filename29, &New_len_data_filename29);

    int data_compare = memcmp(filename29_data, read_pointer_filename29, New_len_data_filename29);

    if (data_compare != 0 || New_len_data_filename29 != len_data_filename29 || value_readfile_test != FILESYSTEM_OK)
    {
        failed_test[4]++;
        correct_test = 0;
    }

    // testing triying to read a non existing filename

    unsigned char *filename30 = "filename30";
    if (API_FS_read_file_data(filename30, strlen(filename30), &test_read2, &test_read1) != FS_NOT_EXISTANT_FILENAME)
    {
        failed_test[5]++;
        correct_test = 0;
    }

    // testing detection of data corruption

    fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE + 100, SEEK_SET); // size of metadata block + current offset of file29
    fwrite(buffercorrompe, sizeof(buffercorrompe), 1, fd);
    fclose(fd); // secure writing in the file

    if (API_FS_read_file_data(filename29, strlen(filename29), &read_pointer_filename29, &New_len_data_filename29) != FS_CORRUPTED_DATA)
    {
        failed_test[6]++;
        correct_test = 0;
    }

    if (correct_test)
    {
        printf("\x1B[32m"
               "tests of API_FS_read_file_data passed correctly"
               "\x1B[0m"
               "\n");
    }
    else
    {
        print_test_Result(failed_test, "API_FS_read_file_data");
        correct_test = 1;
        finalvalue = 0;
    }

    printf("\x1B[34m"
           "\nAPI_FS_rename_file TESTING "
           "\x1B[0m"
           "\n");

    // testing correct parameter checking

    if (API_FS_rename_file(NULL, strlen(filename29), filename30, strlen(filename30)) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[0]++;
        correct_test = 0;
    }
    if (API_FS_rename_file(filename29, MAX_FILENAME_LENGTH + 1, filename30, strlen(filename30)) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[1]++;
        correct_test = 0;
    }
    if (API_FS_rename_file(filename29, strlen(filename29), NULL, strlen(filename30)) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[2]++;
        correct_test = 0;
    }
    if (API_FS_rename_file(filename29, strlen(filename29), filename30, MAX_FILENAME_LENGTH + 1) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[3]++;
        correct_test = 0;
    }

    // testing correct rename
    if (API_FS_rename_file(filename29, strlen(filename29), filename30, strlen(filename30)) != FILESYSTEM_OK)
    {
        failed_test[4]++;
        correct_test = 0;
    }

    // testing triying to rename a non existing file

    if (API_FS_rename_file(filename29, strlen(filename29), filename30, strlen(filename30)) != FS_NOT_EXISTANT_FILENAME)
    {
        failed_test[5]++;
        correct_test = 0;
    }

    if (correct_test)
    {
        printf("\x1B[32m"
               "tests of API_FS_rename_file passed correctly"
               "\x1B[0m"
               "\n");
    }
    else
    {
        print_test_Result(failed_test, "API_FS_rename_file");
        correct_test = 1;
        finalvalue = 0;
    }

    printf("\x1B[34m"
           "\nAPI_FS_update_file_data TESTING "
           "\x1B[0m"
           "\n");

    // testing correct parameter checking

    unsigned char *data_more = "this is not a random generated test, I wrote it because idk what to write for the test,this data have more than 100 characters";
    unsigned char *data_less = "this is not a random generated test, this data have less than 100 characters";

    if (API_FS_update_file_data(NULL, strlen(filename4), data_more, strlen(data_more)) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[0]++;
        correct_test = 0;
    }
    if (API_FS_update_file_data(filename4, MAX_FILENAME_LENGTH + 1, data_more, strlen(data_more)) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[1]++;
        correct_test = 0;
    }
    if (API_FS_update_file_data(filename4, strlen(filename4), NULL, strlen(data_more)) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[2]++;
        correct_test = 0;
    }
    if (API_FS_update_file_data(filename4, strlen(filename4), data_more, MAX_FILE_DATA + 1) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[3]++;
        correct_test = 0;
    }

    // testing triying to update a non existant file

    if (API_FS_update_file_data(filename29, strlen(filename29), data_more, strlen(data_more)) != FS_NOT_EXISTANT_FILENAME)
    {
        failed_test[4]++;
        correct_test = 0;
    }

    // testing data corruption before update :

    fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE + 300, SEEK_SET); // size of metadata block + current offset of file4
    fwrite(buffercorrompe, sizeof(buffercorrompe), 1, fd);
    fclose(fd); // secure writing in the file

    if (API_FS_update_file_data(filename4, strlen(filename4), buffercorrompe, strlen(buffercorrompe)) != FS_CORRUPTED_DATA)
    {
        failed_test[5]++;
        correct_test = 0;
    }

    // tetsing correct update if size <= actual file size

    if (API_FS_update_file_data(filename4, strlen(filename4), data_less, strlen(data_less)) != FILESYSTEM_OK)
    {
        failed_test[6]++;
        correct_test = 0;
    }

    // testing correct update if size > actual file size
    // printing actual filesystem :

    if (API_FS_update_file_data(filename4, strlen(filename4), data_more, strlen(data_more)) != FILESYSTEM_OK)
    {
        failed_test[7]++;
        correct_test = 0;
        printf("aqui falla\n");
    }

    // testing if old data is correctly zeroized

    unsigned char delete_buffer_test2[76];
    fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE + 280, SEEK_SET); // size of metadata block + current offset of filename4
    fread(delete_buffer_test2, 76, 1, fd);
    fclose(fd);

    for (int i = 0; i < sizeof(delete_buffer_test2); i++)
    {
        if (delete_buffer_test2[i] != 0x55)
        {
            failed_test[8]++;
            correct_test = 0;
            break;
        }
    }

    // testing if there is no size for the new updated file size, in the filesystem

    if (API_FS_update_file_data(filename6, strlen(filename6), data_more, MAX_FILE_DATA) != FS_MAX_SIZE_REACHED)
    {
        failed_test[9]++;
        correct_test = 0;
    }

    if (correct_test)
    {
        printf("\x1B[32m"
               "tests of API_FS_update_file_data passed correctly"
               "\x1B[0m"
               "\n");
    }
    else
    {
        print_test_Result(failed_test, "API_FS_update_file_data");
        correct_test = 1;
        finalvalue = 0;
    }

    printf("\x1B[34m"
           "\nAPI_FS_write_buffer_to_file TESTING "
           "\x1B[0m"
           "\n");

    unsigned char *writeread_test_buffer = "this buffer is going to be utilized to test the write and red from a file functions, I hope it works";
    unsigned char *write_buffer_test = "writing this in a file!";

    API_FS_update_file_data(filename1, strlen(filename1), writeread_test_buffer, strlen(writeread_test_buffer));

    // testing correct parameter checking

    if (API_FS_write_buffer_to_file(NULL, strlen(filename1), write_buffer_test, strlen(write_buffer_test), 10) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[0]++;
        correct_test = 0;
    }
    if (API_FS_write_buffer_to_file(filename1, MAX_FILENAME_LENGTH + 1, write_buffer_test, strlen(write_buffer_test), 10) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[1]++;
        correct_test = 0;
    }
    if (API_FS_write_buffer_to_file(filename1, strlen(filename1), NULL, strlen(write_buffer_test), 10) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[2]++;
        correct_test = 0;
    }
    if (API_FS_write_buffer_to_file(filename1, strlen(filename1), write_buffer_test, MAX_FILE_DATA + 1, 10) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[3]++;
        correct_test = 0;
    }

    // testing you cannot write on a non-existing file

    if (API_FS_write_buffer_to_file(filename2, strlen(filename2), write_buffer_test, strlen(write_buffer_test), 10) != FS_NOT_EXISTANT_FILENAME)
    {
        failed_test[4]++;
        correct_test = 0;
    }

    // testing you cannot write more size than the size of the current size of the file

    if (API_FS_write_buffer_to_file(filename1, strlen(filename1), writeread_test_buffer, strlen(writeread_test_buffer), 1) != FS_MAX_SIZE_REACHED)
    {
        failed_test[5]++;
        correct_test = 0;
    }

    // testing correct buffer write on a file :

    if (API_FS_write_buffer_to_file(filename1, strlen(filename1), write_buffer_test, strlen(write_buffer_test), 12) != FILESYSTEM_OK)
    {
        failed_test[6]++;
        correct_test = 0;
    }
    unsigned char *write_buffer_result = "this buffer writing this in a file! to test the write and red from a file functions, I hope it works";

    unsigned char *write_buffer_test2;
    int length_write_buffer;

    API_FS_read_file_data(filename1, strlen(filename1), &write_buffer_test2, &length_write_buffer);

    for (int i = 0; i < length_write_buffer; i++)
    {
        if (write_buffer_test2[i] != write_buffer_result[i])
        {
            failed_test[7]++;
            correct_test = 0;
        }
    }

    if (correct_test)
    {
        printf("\x1B[32m"
               "tests of API_FS_write_buffer_to_file passed correctly"
               "\x1B[0m"
               "\n");
    }
    else
    {
        print_test_Result(failed_test, "API_FS_write_buffer_to_file");
        correct_test = 1;
        finalvalue = 0;
    }

    printf("\x1B[34m"
           "\n API_FS_read_buffer_from_file TESTING "
           "\x1B[0m"
           "\n");

    unsigned char read_pointer_test[2000000];

    // testing correct parameter checking

    if (API_FS_read_buffer_from_file(NULL, strlen(filename1), read_pointer_test, strlen(write_buffer_test), 12) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[0]++;
        correct_test = 0;
    }
    if (API_FS_read_buffer_from_file(filename1, MAX_FILENAME_LENGTH + 1, read_pointer_test, strlen(write_buffer_test), 12) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[1]++;
        correct_test = 0;
    }
    if (API_FS_read_buffer_from_file(filename1, strlen(filename1), NULL, strlen(write_buffer_test), 12) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[2]++;
        correct_test = 0;
    }
    if (API_FS_read_buffer_from_file(filename1, strlen(filename1), read_pointer_test, MAX_FILE_DATA + 1, 12) != FS_INCORRECT_ARGUMENT_ERROR)
    {
        failed_test[3]++;
        correct_test = 0;
    }

    // testing you cannot read on a non-existing file

    if (API_FS_read_buffer_from_file(filename2, strlen(filename2), read_pointer_test, strlen(write_buffer_test), 12) != FS_NOT_EXISTANT_FILENAME)
    {
        failed_test[4]++;
        correct_test = 0;
    }

    // testing you cannot read more size than the current size of the file

    if (API_FS_read_buffer_from_file(filename1, strlen(filename1), read_pointer_test, strlen(writeread_test_buffer), 1) != FS_MAX_SIZE_REACHED)
    {
        failed_test[5]++;
        correct_test = 0;
    }

    // tetsing correct buffer reading on a file:

    if (API_FS_read_buffer_from_file(filename1, strlen(filename1), read_pointer_test, strlen(write_buffer_test), 12) != FILESYSTEM_OK)
    {
        failed_test[6]++;
        correct_test = 0;
    }

    for (int i = 0; i < strlen(write_buffer_test); i++)
    {
        if (read_pointer_test[i] != write_buffer_test[i])
        {
            failed_test[7]++;
            correct_test = 0;
        }
    }

    if (correct_test)
    {
        printf("\x1B[32m"
               "tests of API_FS_read_buffer_from_file passed correctly"
               "\x1B[0m"
               "\n");
    }
    else
    {
        print_test_Result(failed_test, "API_FS_read_buffer_from_file");
        correct_test = 1;
        finalvalue = 0;
    }
    print_files();
    printf("\x1B[34m"
           "\n API_FS_zeroize_file_system TESTING "
           "\x1B[0m"
           "\n");

    // testing correct zeroization

    if (API_FS_zeroize_file_system() != FILESYSTEM_OK)
    {
        failed_test[0]++;
        correct_test = 0;
    }

    unsigned char delete_buffer_test3[MAX_FILE_DATA];
    fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE + 600, SEEK_SET); // size of metadata block + current offset of filename4
    fread(delete_buffer_test2, 126, 1, fd);
    fclose(fd);

    for (int i = 0; i < 126; i++)
    {
        if (delete_buffer_test2[i] != 0x55)
        {
            failed_test[1]++;
            correct_test = 0;
            break;
        }
    }

    fd = fopen(file_system_rpath, "rb+");
    fseek(fd, METADATA_SIZE + 34000600, SEEK_SET); // size of metadata block + current offset of filename4
    fread(delete_buffer_test2, 2000000, 1, fd);
    fclose(fd);

    for (int i = 0; i < 2000000; i++)
    {
        if (delete_buffer_test2[i] != 0x55)
        {
            failed_test[1]++;
            correct_test = 0;
            break;
        }
    }

    if (correct_test)
    {
        printf("\x1B[32m"
               "tests of API_FS_zeroize_file_system passed correctly"
               "\x1B[0m"
               "\n");
    }
    else
    {
        print_test_Result(failed_test, "API_FS_zeroize_file_system");
        correct_test = 1;
        finalvalue = 0;
    }

    if (finalvalue == 1)
    {
        printf("\x1B[32m\n\n     ALL FILE_SYSTEM TESTS PASSED CORRECTLY       \x1B[0m\n");
    }
    else
    {
        printf("\x1B[31m"
               "\n\n                FILESYSTEM TESTS FAILED, CHECK WHICH TESTS FAILED AND CORRECT IT"
               "\x1B[0m"
               "\n");
    }

    API_FS_Close_filesystem();
}
