cmake_minimum_required(VERSION 3.10)

# project details
project(CircuitZKP VERSION 1.0)
set(PROVER_EXEC_NAME circuit_prover)
set(VERIFIER_EXEC_NAME circuit_verifier)
set(LIBRARY_NAME circuit_app_lib)
set(LIBRARY_NAME_SHARED circuit_app_lib_shared)

# turn on gdb
set(CMAKE_BUILD_TYPE Debug)

# packages
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(Boost)
# include(Cryptopp)
include(CTest)
include(Doctest)
include(Documentation)
include(Warnings)
include(Curses)

# add shared libraries
set(SOURCES_SHARED
  src-shared/circuit.cxx
  src-shared/messages.cxx
  src-shared/logger.cxx
  src-shared/util.cxx)
add_library(${LIBRARY_NAME_SHARED} ${SOURCES_SHARED})
target_include_directories(${LIBRARY_NAME_SHARED} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared)
target_link_libraries(${LIBRARY_NAME_SHARED} PUBLIC doctest)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp)
# target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp-shared)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${Boost_LIBRARIES})
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${CURSES_LIBRARIES})

# add student libraries
set(SOURCES
  src/pkg/prover.cxx
  src/pkg/verifier.cxx
  src/drivers/cli_driver.cxx
  src/drivers/crypto_driver.cxx
  src/drivers/network_driver.cxx
)
add_library(${LIBRARY_NAME} ${SOURCES})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(${LIBRARY_NAME} PRIVATE ${LIBRARY_NAME_SHARED})


add_executable(${PROVER_EXEC_NAME} src/cmd/prover.cxx)
target_link_libraries(${PROVER_EXEC_NAME} PRIVATE ${LIBRARY_NAME})

add_executable(${VERIFIER_EXEC_NAME} src/cmd/verifier.cxx)
target_link_libraries(${VERIFIER_EXEC_NAME} PRIVATE ${LIBRARY_NAME})

# properties
set_target_properties(
  ${LIBRARY_NAME}
  ${PROVER_EXEC_NAME}
  ${VERIFIER_EXEC_NAME}
    PROPERTIES
      CXX_STANDARD 20
      CXX_STANDARD_REQUIRED YES
      CXX_EXTENSIONS YES
)

# add tests
add_subdirectory(test)
add_custom_target(check ./test.sh)
