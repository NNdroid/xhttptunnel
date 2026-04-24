#!/bin/bash

# 项目名称，默认使用目录名或自定义
APP_NAME="xhttptunnel"
# 编译输出目录
BUILD_DIR="./bin"
# 源代码入口
MAIN_FILE="main.go"

# 生成版本号: 1.0.yyyyMMdd.githash前7位
BUILD_DATE=$(date +%Y%m%d)
GIT_HASH=$(git rev-parse --short=7 HEAD 2>/dev/null || echo "unknown")
VERSION="1.0.${BUILD_DATE}.${GIT_HASH}"

echo "--- 准备构建版本: ${VERSION} ---"

# 清理旧的编译文件
echo "--- 正在清理构建目录 ---"
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

# 待编译的任务列表 (操作系统/架构)
# 涵盖了主流桌面、服务器、树莓派、传统路由器(mips)及软路由(freebsd)
platforms=(
    "linux/amd64"
    "linux/arm64"
    "linux/arm"
    "linux/386"
    "linux/mips"
    "linux/mipsle"
    "linux/mips64"
    "linux/mips64le"
    "windows/amd64"
    "windows/arm64"
    "windows/386"
    "darwin/amd64"
    "darwin/arm64"
    "freebsd/amd64"
    "freebsd/arm64"
    "openbsd/amd64"
)

echo "--- 开始编译 Go 项目 ---"
go mod tidy
# 移除 go get -u，避免在自动化构建中意外升级依赖导致不兼容，推荐在开发阶段手动执行
# go get -u

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
    # 增加 -X main.Version=${VERSION} 将版本号注入到 Go 代码中
    env CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH \
        go build -ldflags="-s -w -X 'main.Version=${VERSION}'" -o $BUILD_DIR/$output_name $MAIN_FILE

    if [ $? -ne 0 ]; then
        echo "错误: 编译 $platform 失败"
        exit 1
    fi
done

echo "--- 编译完成！文件位于 $BUILD_DIR 目录下 ---"
ls -lh $BUILD_DIR