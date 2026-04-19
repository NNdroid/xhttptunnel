#!/bin/bash

# ==========================================
# 颜色定义
# ==========================================
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

set -e 

echo -e "${BLUE}======================================================${NC}"
echo -e "${YELLOW}🚀 开始执行 XHTTP 隧道项目自动化测试与基准评估...${NC}"
echo -e "${BLUE}======================================================${NC}\n"

if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ 致命错误: 未检测到 Go 语言环境！${NC}"
    exit 1
fi

if [ ! -f "main_test.go" ]; then
    echo -e "${RED}❌ 致命错误: 未找到 main_test.go！${NC}"
    exit 1
fi

echo -e "${GREEN}==> [1/3] 正在格式化代码并整理依赖 (go mod tidy & go fmt)...${NC}"
go mod tidy
go fmt ./...
echo -e "代码格式化完成。\n"

# ==========================================
# 核心修复：强制显式赋值宿主机环境，防止交叉编译导致测试运行失败
# ==========================================
export GOOS=$(go env GOHOSTOS)
export GOARCH=$(go env GOHOSTARCH)
echo -e "${YELLOW}ℹ️ 已显式锁定测试环境: GOOS=${GOOS}, GOARCH=${GOARCH}${NC}\n"

set +e 
echo -e "${GREEN}==> [2/3] 正在运行功能性单元测试 (go test -v)...${NC}"
go test -v ./...
TEST_RESULT=$?

if [ $TEST_RESULT -ne 0 ]; then
    echo -e "\n${RED}❌ 单元测试未通过！基准测试已取消。请先修复上述代码错误。${NC}"
    exit 1
else
    echo -e "${GREEN}✅ 单元测试全部通过！${NC}\n"
fi
set -e

echo -e "${GREEN}==> [3/3] 正在运行性能基准测试并统计内存分配 (go test -bench)...${NC}"
go test -bench=. -benchmem -run=^$ ./...
BENCH_RESULT=$?

if [ $BENCH_RESULT -eq 0 ]; then
    echo -e "\n${BLUE}======================================================${NC}"
    echo -e "${YELLOW}🎉 恭喜！所有测试和性能基准评估已顺利完成！${NC}"
    echo -e "${BLUE}======================================================${NC}"
else
    echo -e "\n${RED}❌ 基准测试执行异常！${NC}"
fi