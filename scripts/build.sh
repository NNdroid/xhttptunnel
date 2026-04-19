#!/bin/bash

# 项目名称，默认使用目录名或自定义
APP_NAME="xhttptunnel"
# 编译输出目录
BUILD_DIR="./bin"
# 源代码入口
MAIN_FILE="main.go"

# 清理旧的编译文件
echo "--- 正在清理构建目录 ---"
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

# 待编译的任务列表 (操作系统/架构)
# 格式: "GOOS/GOARCH"
platforms=(
    "linux/amd64"
    "linux/arm64"
    "linux/arm"
    "windows/amd64"
    "darwin/amd64"
    "darwin/arm64"
)

echo "--- 开始编译 Go 项目 ---"
go mod tidy
go get -u

for platform in "${platforms[@]}"
do
    # 拆分平台字符串
    platform_split=(${platform//\// })
    GOOS=${platform_split[0]}
    GOARCH=${platform_split[1]}
    
    # 设置可执行文件后缀
    output_name=$APP_NAME'-'$GOOS'-'$GOARCH
    if [ $GOOS = "windows" ]; then
        output_name+='.exe'
    fi

    echo "正在构建: $GOOS/$GOARCH -> $output_name"

    # 执行编译
    # CGO_ENABLED=0 确保静态链接，提高跨分发版的兼容性
    env CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o $BUILD_DIR/$output_name $MAIN_FILE

    if [ $? -ne 0 ]; then
        echo "错误: 编译 $platform 失败"
        exit 1
    fi
done

echo "--- 编译完成！文件位于 $BUILD_DIR 目录下 ---"
ls -lh $BUILD_DIR