cmake_minimum_required(VERSION 3.0)

project(main)

# 将src文件夹内的内容用 SRC_LIST保存
aux_source_directory(./src SRC_LIST)

# add_compile_options(-std=c++11) #c99支持for循环内初始化变量
link_directories(/usr/lib64/mysql)

add_executable(main ${SRC_LIST}) # 注意用的花括号
add_definitions(-D _DEBUG)

include(FindPCAP.cmake)
target_link_libraries(main ${PCAP_LIBRARY} mysqlclient pthread ssl crypto)

