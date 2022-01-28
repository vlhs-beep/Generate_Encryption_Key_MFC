cmake_minimum_required(VERSION 3.20)
project(Generate_Encryption_Key_MFC)

set(CMAKE_CXX_STANDARD 14)

set (CMAKE_CXX_FLAGS "-static -static-libgcc -static-libstdc++ -Wl,-Bstatic -lstdc++ -lpthread")

include_directories("chilkat/include")

set(Chilkat_Lib ${CMAKE_SOURCE_DIR}/chilkat/libchilkat-9.5.0.a)

add_executable(Generate_Encryption_Key_MFC main.cpp)

target_link_libraries(Generate_Encryption_Key_MFC ${Chilkat_Lib} winmm.lib sapi wsock32 ws2_32 crypt32 ws2_32 gdiplus)
