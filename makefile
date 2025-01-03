# 编译器和工具链设置
CC = ctc.exe
ASM = astc.exe
AR = artc.exe
LTC = ltc.exe


# 目录设置
LIB_SRC_DIR = library
THIRD_PARTY_DIR = 3rdparty
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/object
LIB_DIR = lib
INCLUDE_DIR = include

CFLAGS = -I"$(INCLUDE_DIR)" -I"." $(INCLUDE_FLAGS)

# 自动查找所有头文件目录
INCLUDE_DIRS := $(shell dir /s /b /ad "$(INCLUDE_DIR)" 2>nul)
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I"$(dir)") -I"$(SRC_DIR)"

# 设置静默模式
Q = @

# 自动查找所有头文件目录（包括3rdparty下的所有子目录）
INCLUDE_DIRS := $(shell dir /s /b /ad "$(INCLUDE_DIR)" "$(THIRD_PARTY_DIR)" 2>nul)
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I"$(dir)")

# 查找所有 .c 文件（包括library和3rdparty目录）
SRCS := $(wildcard $(LIB_SRC_DIR)/*.c) $(wildcard $(THIRD_PARTY_DIR)/*/*.c)
OBJS := $(patsubst $(LIB_SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(patsubst $(THIRD_PARTY_DIR)/%.c,$(OBJ_DIR)/3rdparty/%.o,$(SRCS)))
SRC_TEMPS := $(OBJS:.o=.src)

# 目标库
TARGET = $(LIB_DIR)/libmylibrary.a

# 默认目标改为 build
.DEFAULT_GOAL := build

# 初始化目录
init:
	$(Q)if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)" >nul 2>&1
	$(Q)if not exist "$(OBJ_DIR)" mkdir "$(OBJ_DIR)" >nul 2>&1
	$(Q)if not exist "$(OBJ_DIR)\3rdparty" mkdir "$(OBJ_DIR)\3rdparty" >nul 2>&1
	$(Q)if not exist "$(LIB_DIR)" mkdir "$(LIB_DIR)" >nul 2>&1

# 清理所有构建文件
clean:
	$(Q)echo Cleaning all built files...
	$(Q)if exist "$(BUILD_DIR)" rd /S /Q "$(BUILD_DIR)" >nul 2>&1
#	$(Q)if exist "$(TARGET)" del /Q "$(TARGET)" >nul 2>&1
	$(Q)echo Clean completed.

# 构建目标
build: $(TARGET)

# 重新构建（先清理后构建）
rebuild: clean build

# 编译规则 - library目录
$(OBJ_DIR)/%.src: $(LIB_SRC_DIR)/%.c | init
	$(Q)echo [CC] $(notdir $<)
	$(Q)$(CC) "$<" -o "$@" $(CFLAGS)

$(OBJ_DIR)/%.o: $(OBJ_DIR)/%.src
	$(Q)echo [AS] $(notdir $<)
	$(Q)$(ASM) "$<" -o "$@"

# 编译规则 - 3rdparty目录
$(OBJ_DIR)/3rdparty/%.src: $(THIRD_PARTY_DIR)/%.c | init
	$(Q)if not exist "$(dir $@)" mkdir "$(dir $@)" >nul 2>&1
	$(Q)echo [CC] 3rdparty/$(notdir $<)
	$(Q)$(CC) "$<" -o "$@" $(CFLAGS)

$(OBJ_DIR)/3rdparty/%.o: $(OBJ_DIR)/3rdparty/%.src
	$(Q)echo [AS] 3rdparty/$(notdir $<)
	$(Q)$(ASM) "$<" -o "$@"

# 创建静态库
$(TARGET): $(OBJS) | init
	$(Q)echo [AR] $(notdir $@)
	$(Q)$(AR) -r -c "$@" $(OBJS)
	$(Q)$(LTC) --map-file -OtcxyL -lc -lfp -lrt -M -mcrfiklsmnoduq "$@" $(OBJS)
	$(Q)echo Static library created: $(TARGET)
	$(Q)echo Build completed.

# 显示调试信息
debug:
	$(Q)echo Source files:
	$(Q)echo $(SRCS)
	$(Q)echo Object files:
	$(Q)echo $(OBJS)
	$(Q)echo Include directories:
	$(Q)echo $(INCLUDE_DIRS)

# 声明伪目标
.PHONY: clean build rebuild init debug help

# 显示帮助信息
help:
	$(Q)echo Available targets:
	$(Q)echo   build       - Build the project (default)
	$(Q)echo   clean       - Remove all built files
	$(Q)echo   rebuild     - Clean and build again
	$(Q)echo   debug       - Show debug information
	$(Q)echo   help        - Show this help message