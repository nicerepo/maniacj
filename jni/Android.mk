define walk
  $(wildcard $(1)) $(foreach e, $(wildcard $(1)/*), $(call walk, $(e)))
endef

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MULTILIB := both
LOCAL_MODULE := maniacj
LOCAL_SRC_FILES := $(filter %.cc, $(call walk, $(LOCAL_PATH)))

include $(BUILD_EXECUTABLE)
