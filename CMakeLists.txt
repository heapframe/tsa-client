cmake_minimum_required(VERSION 3.25)
project(tsa_client CXX)

set(CMAKE_CXX_STANDARD 20)

option(ENABLE_FREETSA_BUNDLE "Embed FreeTSA cert bundle" ON)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_program(XXD xxd REQUIRED)
find_program(CURL_BIN curl REQUIRED)

add_executable(tsa_client main.cpp)

target_link_libraries(tsa_client
        OpenSSL::SSL
        OpenSSL::Crypto
        CURL::libcurl
)

# -----------------------------------------
# Paths
# -----------------------------------------
set(CERT_DIR "${CMAKE_BINARY_DIR}/certs")

set(CA_FILE   "${CERT_DIR}/cacert.pem")
set(TSA_FILE  "${CERT_DIR}/tsa.crt")
set(BUNDLE    "${CERT_DIR}/freetsa_bundle.pem")
set(HEADER    "${CMAKE_BINARY_DIR}/freetsa_bundle.h")

set(CA_URL  "https://freetsa.org/files/cacert.pem")
set(TSA_URL "https://freetsa.org/files/tsa.crt")

if(ENABLE_FREETSA_BUNDLE)

    target_compile_definitions(tsa_client PRIVATE ENABLE_FREETSA_BUNDLE)

    file(MAKE_DIRECTORY ${CERT_DIR})

    # -----------------------------
    # Step 1: fetch certs (BUILD TIME)
    # -----------------------------
    add_custom_command(
            OUTPUT ${CA_FILE}
            COMMAND ${CURL_BIN} -s ${CA_URL} -o ${CA_FILE}
            COMMENT "Fetching FreeTSA CA"
    )

    add_custom_command(
            OUTPUT ${TSA_FILE}
            COMMAND ${CURL_BIN} -s ${TSA_URL} -o ${TSA_FILE}
            COMMENT "Fetching FreeTSA TSA cert"
    )

    # -----------------------------
    # Step 2: bundle PEM
    # -----------------------------
    add_custom_command(
            OUTPUT ${BUNDLE}
            COMMAND ${CMAKE_COMMAND} -E cat ${CA_FILE} ${TSA_FILE} > ${BUNDLE}
            DEPENDS ${CA_FILE} ${TSA_FILE}
            COMMENT "Building PEM trust bundle"
    )

    # -----------------------------
    # Step 3: generate header
    # -----------------------------
    add_custom_command(
            OUTPUT ${HEADER}
            # 1. Copy the bundle to a file named 'freetsa_bundle' (no extension)
            COMMAND ${CMAKE_COMMAND} -E copy ${BUNDLE} "${CERT_DIR}/freetsa_bundle"
            # 2. Run xxd on that file so it generates 'freetsa_bundle' variables
            COMMAND ${XXD} -i freetsa_bundle > ${HEADER}
            # 3. Clean up the temporary file
            COMMAND ${CMAKE_COMMAND} -E rm "${CERT_DIR}/freetsa_bundle"
            WORKING_DIRECTORY ${CERT_DIR}
            DEPENDS ${BUNDLE}
            COMMENT "Generating embedded cert header with custom names"
    )

    add_custom_target(cert_bundle ALL
            DEPENDS ${HEADER}
    )

    add_dependencies(tsa_client cert_bundle)

    target_include_directories(tsa_client PRIVATE ${CMAKE_BINARY_DIR})

endif()