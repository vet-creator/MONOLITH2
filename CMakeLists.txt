cmake_minimum_required(VERSION 3.15)
project(monolith C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# Core cipher/VM sources shared by every target. vm.c depends on the
# whitebox table-network, the MBA-obfuscated Feistel round, and the DLP
# modular-arithmetic primitives, so all three are part of the shared core
# (every target that links vm.c must link these too, or the build fails to
# link with undefined references). rho.c (Pollard's rho) is deliberately
# NOT here -- only the solver and the self-test need to actually invert the
# discrete-log gate, and the shipped challenge should not carry that code.
set(MONO_CORE
  src/sha256.c
  src/gf.c
  src/spn.c
  src/whitebox.c
  src/mba_feistel.c
  src/dlp.c
  src/vm.c
)

# ---- preflight: report EVERY missing source at once -------------------------
# Without this, CMake fails on the first missing file only, which hides the
# real problem when a whole directory was left out of the commit.
set(MONO_REQUIRED
  ${MONO_CORE}
  src/sha256.h
  src/gf.h
  src/spn.h
  src/whitebox.h
  src/mba_feistel.h
  src/dlp.h
  src/vm.h
  src/rho.h
  src/rho.c
  src/bytecode_def.h
  src/bytecode_def.c
  src/main.c
  tools/generator.c
  tools/solver.c
  tests/selftest.c
  tests/integration.cmake
)
set(MONO_MISSING "")
foreach(f IN LISTS MONO_REQUIRED)
  if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${f})
    list(APPEND MONO_MISSING ${f})
  endif()
endforeach()
if(MONO_MISSING)
  string(REPLACE ";" "\n    " MONO_MISSING_MSG "${MONO_MISSING}")
  message(FATAL_ERROR
    "These source files are missing from the repository:\n"
    "    ${MONO_MISSING_MSG}\n\n"
    "They exist in the MONOLITH release but were not committed. Add them and "
    "push again (empty directories are not tracked by git, so a whole folder "
    "can silently go missing).")
endif()

# ---- build-time generator ---------------------------------------------------
# Emits generated/mono_data.h (encrypted program + target). Links the CLEAR
# program (bytecode_def.c); the shipped challenge does not.
add_executable(mono_gen tools/generator.c src/bytecode_def.c ${MONO_CORE})
target_include_directories(mono_gen PRIVATE src)

set(GEN_DIR ${CMAKE_BINARY_DIR}/generated)
set(GEN_HDR ${GEN_DIR}/mono_data.h)

# The generator runs at BUILD time, so a configure-time MONO_FLAG_INNER would
# otherwise be lost. Capture it here and forward it explicitly. (Setting the
# variable in the build step's environment also works -- both paths are honored.)
set(MONO_FLAG_INNER "$ENV{MONO_FLAG_INNER}" CACHE STRING
    "Flag inner text, exactly 32 characters. Empty = use generator default.")
mark_as_advanced(MONO_FLAG_INNER)

if(MONO_FLAG_INNER STREQUAL "")
  set(MONO_GEN_CMD mono_gen ${GEN_HDR})
else()
  set(MONO_GEN_CMD ${CMAKE_COMMAND} -E env
      "MONO_FLAG_INNER=${MONO_FLAG_INNER}" $<TARGET_FILE:mono_gen> ${GEN_HDR})
endif()

add_custom_command(
  OUTPUT  ${GEN_HDR}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${GEN_DIR}
  COMMAND ${MONO_GEN_CMD}
  DEPENDS mono_gen
  COMMENT "Generating embedded challenge data (mono_data.h)"
  VERBATIM
)
add_custom_target(mono_data DEPENDS ${GEN_HDR})
set_source_files_properties(${GEN_HDR} PROPERTIES GENERATED TRUE)

# ---- the challenge (this IS the CTF target) --------------------------------
add_executable(monolith src/main.c ${MONO_CORE})
add_dependencies(monolith mono_data)
target_include_directories(monolith PRIVATE src ${CMAKE_BINARY_DIR})

# ---- reference solver (designer tool; proves solvability) ------------------
add_executable(mono_solver tools/solver.c src/rho.c ${MONO_CORE})
add_dependencies(mono_solver mono_data)
target_include_directories(mono_solver PRIVATE src ${CMAKE_BINARY_DIR})

# ---- self-test --------------------------------------------------------------
add_executable(mono_selftest tests/selftest.c src/bytecode_def.c src/rho.c ${MONO_CORE})
add_dependencies(mono_selftest mono_data)
target_include_directories(mono_selftest PRIVATE src ${CMAKE_BINARY_DIR})

# MSVC: silence CRT "deprecation" of fopen/sprintf (these uses are fine).
if(MSVC)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# ---- tests ------------------------------------------------------------------
enable_testing()
add_test(NAME selftest COMMAND mono_selftest)
add_test(NAME integration
  COMMAND ${CMAKE_COMMAND}
          -DSOLVER=$<TARGET_FILE:mono_solver>
          -DAPP=$<TARGET_FILE:monolith>
          -P ${CMAKE_SOURCE_DIR}/tests/integration.cmake)
