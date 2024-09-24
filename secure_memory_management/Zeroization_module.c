#include "Zeroization_module.h"

void API_ZM_zeroize_entire_module() {
    API_MT_zeroize_and_free_all();   /**< Zeroize and free all memory tracked by the memory tracker. */
    API_MM_Zeroize_root();           /**< Zeroize the entire memory management tree. */
    API_FS_zeroize_file_system();    /**< Zeroize and wipe the file system. */
}