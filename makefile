# 编译器和工具链设置
CC = ctc.exe
ASM = astc.exe
AR = artc.exe

# 目录设置
SEARCH_ROOT = .
SRC_DIR = src
LIB_DIR = lib
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/object
LIB_DIR = lib
INCLUDE_DIR = include

# 编译选项
CFLAGS = $(INCLUDE_FLAGS)

# 设置静默模式
Q = @

# 自动查找所有头文件目录
INCLUDE_DIRS := $(shell dir /s /b /ad "$(INCLUDE_DIR)" 2>nul)
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I"$(dir)")

# 排除目录
EXCLUDE_DIRS = build lib node_modules .git

# 查找所有 .c 文件，排除特定目录
SRCS := $(shell dir /s /b "$(SEARCH_ROOT)\*.c" 2>nul | findstr /v /i "$(EXCLUDE_DIRS)")
# 生成对应的 .src 和 .o 文件路径
SRC_FILES := $(notdir $(SRCS))
OBJ_FILES := $(SRC_FILES:.c=.o)
OBJS := $(addprefix $(BUILD_DIR)/,$(OBJ_FILES))
# 查找所有 .c 文件
SRCS := $(wildcard $(SRC_DIR)/*.c)
# 生成对应的 .o 文件路径
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
SRC_TEMPS := $(OBJS:.o=.src)

# 目标库
TARGET = $(LIB_DIR)/libmylibrary.a

# 默认目标
all: $(TARGET)

# 初始化目录
init:
	@if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)"
	@if not exist "$(LIB_DIR)" mkdir "$(LIB_DIR)"
	$(Q)if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)" >nul 2>&1
	$(Q)if not exist "$(OBJ_DIR)" mkdir "$(OBJ_DIR)" >nul 2>&1
	$(Q)if not exist "$(LIB_DIR)" mkdir "$(LIB_DIR)" >nul 2>&1

# 清理规则
	$(Q)if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)" >nul 2>&1
	$(Q)if not exist "$(OBJ_DIR)" mkdir "$(OBJ_DIR)" >nul 2>&1
	$(Q)if not exist "$(LIB_DIR)" mkdir "$(LIB_DIR)" >nul 2>&1
# 完全清理
clean:
	@echo Cleaning...
	@if exist "$(BUILD_DIR)" del /Q "$(BUILD_DIR)\*.*" 2>nul
	@if exist "$(TARGET)" del /Q "$(TARGET)" 2>nul
	$(Q)echo Cleaning all built files...
	$(Q)if exist "$(BUILD_DIR)" rd /S /Q "$(BUILD_DIR)" >nul 2>&1
	$(Q)if exist "$(TARGET)" del /Q "$(TARGET)" >nul 2>&1

# 编译规则
$(BUILD_DIR)/%.src: %.c
$(BUILD_DIR)/%.src: $(SRC_DIR)/%.c
	$(CC) "$<" -o "$@" $(CFLAGS)
$(OBJ_DIR)/%.src: $(SRC_DIR)/%.c | init
$(OBJ_DIR)/%.src: $(SRC_DIR)/%.c | init
	$(Q)echo [CC] $(notdir $<)
	$(Q)$(CC) "$<" -o "$@" $(CFLAGS)

$(BUILD_DIR)/%.o: $(BUILD_DIR)/%.src
	@echo Assembling $<...
	$(ASM) "$<" -o "$@"
	@echo Compiling $<...
	$(CC) "$<" -o "$@" $(CFLAGS)

$(OBJ_DIR)/%.o: $(OBJ_DIR)/%.src
$(OBJ_DIR)/%.o: $(OBJ_DIR)/%.src
	$(Q)echo [AS] $(notdir $<)
	$(Q)$(ASM) "$<" -o "$@"

# 创建静态库
$(TARGET): $(OBJS)
	@echo Build completed successfully.
	@echo Library: $(TARGET)
	$(Q)echo [AR] $(notdir $@)
	$(Q)$(AR) -r -c "$@" $(OBJS)
	$(Q)echo Build completed successfully.
	$(Q)echo Output: $(TARGET)

# 声明伪目标
.PHONY: all clean init

# 显示帮助信息
# 显示调试信息
debug:
	@echo Source files: $(SRCS)
	@echo Object files: $(OBJS)
	@echo   help     - Show this help message

	@echo Include dirs: $(INCLUDE_DIRS)


help:
	$(Q)echo Available targets:
	$(Q)echo   all         - Build everything (default)
	$(Q)echo   clean       - Remove all built files
	$(Q)echo   help        - Show this help message
