APP_ABI := armeabi-v7a arm64-v8a x86 x86_64
APP_PLATFORM := android-21
APP_STL := c++_static
APP_CPPFLAGS := -Os -std=c++17 -Werror -Wall -Wpedantic
APP_LDFLAGS := -landroid -llog -ldl
