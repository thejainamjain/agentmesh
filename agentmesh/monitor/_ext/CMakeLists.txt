cmake_minimum_required(VERSION 3.15)
project(interceptor_core)

find_package(Python3 REQUIRED COMPONENTS Interpreter Development)
find_package(pybind11 REQUIRED)
find_package(OpenSSL REQUIRED)

pybind11_add_module(interceptor_core interceptor_core.cpp)
target_link_libraries(interceptor_core PRIVATE OpenSSL::Crypto)

# Output .so directly into _ext/ so Python can import it
set_target_properties(interceptor_core PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

target_compile_options(interceptor_core PRIVATE
    $<$<CONFIG:Release>:-O3 -DNDEBUG>
    $<$<CONFIG:Debug>:-O0 -g>
)
set_property(TARGET interceptor_core PROPERTY CXX_STANDARD 17)
set_property(TARGET interceptor_core PROPERTY CXX_STANDARD_REQUIRED ON)