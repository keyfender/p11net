cmake_minimum_required (VERSION 2.6)
project (libp11net CXX)
include_directories(
    .
    ${PROJECT_BINARY_DIR}
    ${Boost_INCLUDE_DIR}
)
link_directories(
    /usr/local/opt/openssl/lib
    /usr/local/lib
)
add_definitions(-DBOOST_LOG_DYN_LINK -DNDEBUG -DNO_MEMENV -DNO_METRICS)
#set(CMAKE_CXX_FLAGS "-g -Wall -Werror -std=c++11")
add_compile_options(-O2 -Wall -std=c++11)
add_subdirectory(proto_bindings)
#set(Boost_USE_STATIC_LIBS ON)
#find_package(Boost COMPONENTS system chrono thread filesystem log REQUIRED)
find_package(Boost COMPONENTS system chrono thread filesystem log log_setup REQUIRED)
add_library(p11net MODULE
    p11net.cc
    p11net_service.cc
    slot_manager_impl.cc
    session_impl.cc
    object_impl.cc
    object_policy_common.cc
    object_policy_data.cc
    object_policy_cert.cc
    object_policy_key.cc
    object_policy_public_key.cc
    object_policy_private_key.cc
    object_policy_secret_key.cc
    object_pool_impl.cc
    p11net_factory_impl.cc
    object_store_impl.cc
    net_utility_impl.cc
    brillo/secure_blob.cc
    base/logging.cc
    p11net_utility.cc
    attributes.cc
)
target_link_libraries(p11net
    ${Boost_LIBRARIES}
    proto_bindings
    protobuf
    ssl
    crypto
    cpprest
    leveldb
)
