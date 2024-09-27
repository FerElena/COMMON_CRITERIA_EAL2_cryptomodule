#include "State_Machine.h"

static State current_state = STATE_OFF;

int API_SM_State_Change(State next_state){
    switch (current_state) {
        // When the system is off
        case STATE_OFF:
            switch (next_state) {
                case STATE_ON:
                    current_state = STATE_ON;
                    return STATE_CHANGE_SUCCESS;  // Successful transition to ON
                case STATE_SOFTERROR:
                    current_state = STATE_SOFTERROR;
                    return SM_SOFTERROR;  // Transition to soft error
                default:
                    current_state = STATE_ERROR;
                    return SM_ERROR;  // Any other transition is an error
            }
        
        // When the system is on
        case STATE_ON:
            switch (next_state) {
                case STATE_INITIALIZATION:
                    current_state = STATE_INITIALIZATION;
                    return STATE_CHANGE_SUCCESS;  // Successful transition to STATE_INITIALIZATION
                case STATE_SOFTERROR:
                    current_state = STATE_SOFTERROR;
                    return SM_SOFTERROR;  // Transition to soft error
                default:
                    current_state = STATE_ERROR;
                    return SM_ERROR;  // Invalid transition, go to error state
            }
        // During secure initialization of the module
        case STATE_INITIALIZATION:
            switch (next_state) {
                case STATE_SELF_TEST:
                    current_state = STATE_SELF_TEST;
                    return STATE_CHANGE_SUCCESS;  // Transition to STATE_SELF_TEST
                case STATE_SOFTERROR:
                    current_state = STATE_SOFTERROR;
                    return SM_SOFTERROR;  // Transition to soft error
                default:
                    current_state = STATE_ERROR;
                    return SM_ERROR;  // Invalid transition, go to error state
            }
        // During the self-test
        case STATE_SELF_TEST:
            switch (next_state) {
                case STATE_INITIALIZATION:
                    current_state = STATE_INITIALIZATION;
                    return STATE_CHANGE_SUCCESS;  // Successful transition to INITIALIZATION
                case STATE_OPERATIONAL:
                    current_state = STATE_OPERATIONAL;
                    return STATE_CHANGE_SUCCESS;  // Direct transition to OPERATIONAL allowed
                case STATE_SOFTERROR:
                    current_state = STATE_SOFTERROR;
                    return SM_SOFTERROR;  // Transition to soft error
                default:
                    current_state = STATE_ERROR;
                    return SM_ERROR;  // Invalid transition, go to error state
            }
        
        // During operational state
        case STATE_OPERATIONAL:
            switch (next_state) {
                case STATE_CRYPTOGRAPHIC:
                    current_state = STATE_CRYPTOGRAPHIC;
                    return STATE_CHANGE_SUCCESS;  // Successful transition to CRYPTOGRAPHIC
                case STATE_CSP:
                    current_state = STATE_CSP;
                    return STATE_CHANGE_SUCCESS;  // Successful transition to CSP
                case STATE_SELF_TEST:
                    current_state = STATE_SELF_TEST;
                    return STATE_CHANGE_SUCCESS;  // Re-enter SELF-TEST
                case STATE_OFF:
                    current_state = STATE_OFF;
                    return STATE_CHANGE_SUCCESS;  // Transition to OFF
                case STATE_SOFTERROR:
                    current_state = STATE_SOFTERROR;
                    return SM_SOFTERROR;  // Transition to soft error
                default:
                    current_state = STATE_ERROR;
                    return SM_ERROR;  // Invalid transition, go to error state
            }
        
        // During cryptographic operations
        case STATE_CRYPTOGRAPHIC:
            switch (next_state) {
                case STATE_OPERATIONAL:
                    current_state = STATE_OPERATIONAL;
                    return STATE_CHANGE_SUCCESS;  // Successful transition to OPERATIONAL
                case STATE_CSP:
                    current_state = STATE_CSP;
                    return STATE_CHANGE_SUCCESS;  // Transition to CSP
                case STATE_SOFTERROR:
                    current_state = STATE_SOFTERROR;
                    return SM_SOFTERROR;  // Transition to soft error
                default:
                    current_state = STATE_ERROR;
                    return SM_ERROR;  // Invalid transition, go to error state
            }
        
        // During CSP handling
        case STATE_CSP:
            switch (next_state) {
                case STATE_OPERATIONAL:
                    current_state = STATE_OPERATIONAL;
                    return STATE_CHANGE_SUCCESS;  // Transition back to OPERATIONAL
                case STATE_CRYPTOGRAPHIC:
                    current_state = STATE_CRYPTOGRAPHIC;
                    return STATE_CHANGE_SUCCESS;  // Transition to CRYPTOGRAPHIC
                case STATE_SOFTERROR:
                    current_state = STATE_SOFTERROR;
                    return SM_SOFTERROR;  // Transition to soft error
                default:
                    current_state = STATE_ERROR;
                    return SM_ERROR;  // Invalid transition, go to error state
            }
        
        // During a soft error
        case STATE_SOFTERROR:
            switch (next_state) {
                case SM_SOFTERROR:
                    current_state = SM_SOFTERROR;
                    return STATE_CHANGE_SUCCESS;  // Transition to SOFTERROR
                case STATE_SELF_TEST:
                    current_state = STATE_SELF_TEST;
                    return STATE_CHANGE_SUCCESS;  // Transition to SELF-TESTS
                case STATE_ERROR:
                    current_state = STATE_ERROR;
                    return STATE_CHANGE_SUCCESS;  // Transition to SELF-TESTS
                default:
                    current_state = STATE_SOFTERROR;
                    return STATE_CHANGE_SUCCESS;  // Invalid transition, go to error state
            }

        // Default case for invalid states
        default:
            current_state = STATE_ERROR;
            return SM_ERROR;  // Invalid state, enter hard error
    }
}

State API_SM_get_current_state() {
    return current_state;
}

const char* API_SM_get_current_state_name() {
    switch (current_state) {
        case STATE_OFF:
            return "STATE_OFF";
        case STATE_ON:
            return "STATE_ON";
        case STATE_INITIALIZATION:
            return "STATE_INITIALIZATION";
        case STATE_SELF_TEST:
            return "STATE_SELF_TEST";
        case STATE_OPERATIONAL:
            return "STATE_OPERATIONAL";
        case STATE_CRYPTOGRAPHIC:
            return "STATE_CRYPTOGRAPHIC";
        case STATE_CSP:
            return "STATE_CSP";
        case STATE_SOFTERROR:
            return "STATE_SOFTERROR";
        case STATE_ERROR:
            return "STATE_ERROR";
        default:
            return "UNKNOWN_STATE";  // In case of an invalid state
    }
}