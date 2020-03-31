cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

add_definitions (-DMCTP_LOG_STDERR)
add_definitions (-DMCTP_HAVE_FILEIO)
add_definitions (-DMCTP_HAVE_STDIO)
add_definitions (-DMCTP_DEFAULT_ALLOC)

add_library (mctp_intel STATIC alloc.c astlpc.c core.c log.c libmctp.h serial.c astpcie.c smbus.c)

target_include_directories (mctp_intel PUBLIC
                            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                            $<INSTALL_INTERFACE:include/libmctp>)

enable_testing ()

add_executable (test_eid tests/test_eid.c tests/test-utils.c)
target_link_libraries (test_eid mctp_intel)
add_test (NAME eid COMMAND test_eid)

add_executable (test_seq tests/test_seq.c tests/test-utils.c)
target_link_libraries (test_seq mctp_intel)
add_test (NAME seq COMMAND test_seq)

add_executable (test_bridge tests/test_bridge.c tests/test-utils.c)
target_link_libraries (test_bridge mctp_intel)
add_test (NAME bridge COMMAND test_bridge)

add_executable (test_astlpc tests/test_astlpc.c tests/test-utils.c)
target_link_libraries (test_astlpc mctp_intel)
add_test (NAME astlpc COMMAND test_astlpc)

add_executable (test_serial tests/test_serial.c tests/test-utils.c)
target_link_libraries (test_serial mctp_intel)
add_test (NAME serial COMMAND test_serial)

add_executable (test_astpcie tests/test_astpcie.c)
target_link_options(test_astpcie PRIVATE -z muldefs)
target_link_libraries (test_astpcie mctp_intel)
add_test (NAME astpcie COMMAND test_astpcie)

add_executable (test_cmds tests/test_cmds.c tests/test-utils.c)
target_link_libraries (test_cmds mctp_intel)
add_test (NAME control_commands COMMAND test_cmds)

add_executable (test_smbus tests/test_smbus.c)
target_link_libraries (test_smbus mctp_intel)
add_test (NAME smbus COMMAND test_smbus)

install (TARGETS mctp_intel DESTINATION lib)
install (FILES libmctp.h libmctp-cmds.h libmctp-smbus.h libmctp-astpcie.h DESTINATION include)

