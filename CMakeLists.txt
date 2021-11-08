cmake_minimum_required(VERSION 2.8)

project(main)

# 将src文件夹内的内容用 SRC_LIST保存
aux_source_directory(./src SRC_LIST)

add_compile_options(-std=gnu11) #c99支持for循环内初始化变量

add_executable(main ${SRC_LIST}) # 注意用的花括号

