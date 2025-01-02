include_directories(
    ../Catch2/single_include
    ../include
)

add_executable (unit-tests
    test_sha224.cpp
    test_sha256.cpp
    test_sha384.cpp
    test_sha512.cpp
    test_sha512_224.cpp
    test_sha512_256.cpp
    test_util.cpp
)

add_test(NAME unit-tests COMMAND $<TARGET_FILE:unit-tests>)
