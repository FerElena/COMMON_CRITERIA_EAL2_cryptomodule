#ifndef STATE_MACHINE_H
#define STATE_MACHINE_H

/*
ON ----> SELF-TEST ----> INITIALIZATION ----------->OPERATIONAL
 |         |                  |                /         |        \
 |         v                  v               v          v        v
 +-------> ERROR <------------ ERROR <------OFF    CRYPTOGRAPHIC  CSP
                                                \     |     /
                                                v     v    v
                                                    ERROR
*/

// Definition of all possible states in the cryptographic system's state machine
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

// Initially, the system is off
State current_state = STATE_OFF;


void State_Change(State);

#endif