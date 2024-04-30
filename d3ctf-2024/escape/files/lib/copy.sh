#!/bin/bash

# 检查 libs.txt 文件是否存在
if [ ! -f libs.txt ]; then
    echo "libs.txt 文件不存在。"
    exit 1
fi

# 读取 libs.txt 文件中的每一行
while IFS= read -r line
do
    # 使用 grep 和 awk 提取出路径
    lib_path=$(echo "$line" | grep -oP '(?<=> )/\S+')
    # 检查路径是否为空或者是虚拟的动态链接库（不实际存在于文件系统中）
    if [[ ! -z "$lib_path" && ! "$lib_path" == linux-vdso.so* ]]; then
        # 复制库文件到当前目录，添加 -v 参数以显示详细的复制信息
        cp -v "$lib_path" .
    fi
done < libs.txt

# 打印完成的消息
echo "所有库文件已复制到当前目录。"

