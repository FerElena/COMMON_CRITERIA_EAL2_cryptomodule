/**
 * @file state_machine.h
 * @brief Header file for the state machine of a cryptographic system.
 *
 * This file contains the definition of the states and the function for handling state transitions.
 * The state machine manages various operational modes of the system, including transitions between 
 * operational, cryptographic, and error states.
 */

/*
ON ----> INITIALIZATION ----> SELF-TEST ----------->OPERATIONAL
 |         |                  |                /         |        \
 |         v                  v               v          v        v
 +-------> ERROR <------------ ERROR <------OFF    CRYPTOGRAPHIC  CSP
                                                \     |     /
                                                v     v    v
                                                    ERROR
*/

#ifndef STATE_MACHINE_H
#define STATE_MACHINE_H

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

/**
 * @brief Define constants for state change return codes.
 *
 * These constants indicate the result of a state change, allowing for more precise
 * tracking of whether the state transition was successful, or if an error (soft or hard) occurred.
 */

#define STATE_CHANGE_SUCCESS 1800         // Successful state change
#define SM_ERROR -1800          // Hard error state
#define SM_SOFTERROR -1801      // Soft error state
#define SM_ERROR_STATE -1802  //Invalid operation for this state

/**
 * @enum State
 * @brief Enumerates the possible states for the cryptographic system's state machine.
 *
 * This enumeration defines the different states the system can be in. The state machine
 * transitions between these states depending on the system's operational phase and error conditions.
 */

typedef enum {
    STATE_ON,               // System is powered on
    STATE_SELF_TEST,        // System performs a self-test to ensure it operates correctly
    STATE_INITIALIZATION,   // System initializes settings and components after passing the self-test
    STATE_OPERATIONAL,      // System is fully operational and can perform standard tasks
    STATE_CRYPTOGRAPHIC,    // System is engaged in cryptographic operations (e.g., encryption/decryption)
    STATE_CSP,              // System is handling Critical Security Parameters (CSP) like keys
    STATE_SOFTERROR,        // Error state for handling faults or failures in any state
    STATE_ERROR,            // module integrity compromised, ZEROIZATION initialized
    STATE_OFF               // System is powered off
} State;

/**
 * @var current_state
 * @brief Stores the current state of the system.
 *
 * This global variable holds the system's current state. It is initialized to `STATE_OFF`, 
 * indicating that the system is powered off at startup.
 */

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief Handles state transitions in the cryptographic system.
 *
 * This function manages the state transitions in the cryptographic system. It takes the next state 
 * as input and attempts to transition the system to that state. If the transition is valid, 
 * it updates the `current_state` and returns a success code. If the transition is invalid, 
 * the system enters an error state, either soft or hard, and the corresponding error code is returned.
 *
 * @param next_state The next state to which the system should transition.
 * @return int Returns a constant indicating the result of the state change:
 *  - `STATE_CHANGE_SUCCESS`: Indicates the state change was successful.
 *  - `SM_ERROR`: Indicates the state change led to a hard error.
 *  - `SM_SOFTERROR`: Indicates the state change led to a soft error.
 */

int API_SM_State_Change(State next_state);


/**
 * @brief Retrieves the current state of the system.
 *
 * This function returns the current state of the state machine
 * as an enumerated value of type `State`.
 *
 * @return The current state of the system.
 */

State API_SM_get_current_state();

/**
 * @brief Get the name of the current state.
 * 
 * @return const char* A pointer to a static string representing the current state name.
 */

const char* API_SM_get_current_state_name();

#endif