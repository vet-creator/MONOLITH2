# Cross-platform end-to-end test:
#   - the solver recovers the flag from the shipped data
#   - the challenge ACCEPTS that flag (exit 0)
#   - the challenge REJECTS a mutated flag (non-zero)
#
# Invoked via: cmake -DSOLVER=... -DAPP=... -P integration.cmake
# The recovered flag is never printed, so CI logs never leak a custom secret.

if(NOT DEFINED SOLVER OR NOT DEFINED APP)
  message(FATAL_ERROR "SOLVER and APP must be defined")
endif()

execute_process(
  COMMAND "${SOLVER}"
  OUTPUT_VARIABLE FLAG
  RESULT_VARIABLE R_SOLVE
  OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT R_SOLVE EQUAL 0)
  message(FATAL_ERROR "solver failed with code ${R_SOLVE}")
endif()

set(GOOD "${CMAKE_CURRENT_LIST_DIR}/../_good.in")
file(WRITE "${GOOD}" "${FLAG}\n")

execute_process(
  COMMAND "${APP}"
  INPUT_FILE "${GOOD}"
  RESULT_VARIABLE R_GOOD
  OUTPUT_QUIET ERROR_QUIET)
if(NOT R_GOOD EQUAL 0)
  message(FATAL_ERROR "challenge rejected the correct flag (code ${R_GOOD})")
endif()

# Mutate the last inner character to build a wrong-but-well-formed flag.
# Pick a replacement that differs from the original, whatever it is.
string(LENGTH "${FLAG}" L)
math(EXPR CUT "${L} - 2")
string(SUBSTRING "${FLAG}" 0 ${CUT} HEAD)
string(SUBSTRING "${FLAG}" ${CUT} 1 LAST)
if(LAST STREQUAL "~")
  set(SWAP "!")
else()
  set(SWAP "~")
endif()
set(BAD "${CMAKE_CURRENT_LIST_DIR}/../_bad.in")
file(WRITE "${BAD}" "${HEAD}${SWAP}}\n")

execute_process(
  COMMAND "${APP}"
  INPUT_FILE "${BAD}"
  RESULT_VARIABLE R_BAD
  OUTPUT_QUIET ERROR_QUIET)
if(R_BAD EQUAL 0)
  message(FATAL_ERROR "challenge accepted a wrong flag")
endif()

file(REMOVE "${GOOD}" "${BAD}")
message(STATUS "integration: correct flag accepted, wrong flag rejected -- OK")
