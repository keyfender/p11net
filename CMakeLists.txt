cmake_minimum_required (VERSION 2.6)
project (libchaps)
include_directories(
	.
	${PROJECT_BINARY_DIR}
	${PROJECT_SOURCE_DIR}/../Chromium/src
)
link_directories(
	/usr/local/opt/openssl/lib
	/usr/local/lib
	${PROJECT_SOURCE_DIR}/../Chromium/src/out/Default/obj/base
	${PROJECT_SOURCE_DIR}/../Chromium/src/out/Default/obj/base/third_party/dynamic_annotations
)
set(CMAKE_CXX_FLAGS "-g -Wall -Werror -std=c++11 -DCOMPILER_GCC -DARCH_CPU_X86_FAMILY -DOS_POSIX -DWCHAR_T_IS_UTF32 -DOS_MACOSX -DNDEBUG -DNO_MEMENV -DNO_METRICS")
add_subdirectory(proto_bindings)
add_library(p11net MODULE
	chaps.cc
	chaps_service.cc 
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
	chaps_factory_impl.cc 
	object_store_impl.cc 
	net_utility_impl.cc 
	brillo/secure_blob.cc
	chaps_utility.cc
	attributes.cc
)
target_link_libraries(p11net
	proto_bindings
	protobuf
	event
	ssl
	crypto
	boost_system
	boost_chrono
	boost_thread-mt
	cpprest
	base
	base_static
	leveldb
	"-framework CoreFoundation"
	"-framework AppKit"
	"-framework Security"
	dynamic_annotations
)
