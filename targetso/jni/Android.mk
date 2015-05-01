LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
$(call import-add-path,E:\hool_helloworld\targetso\jni)
LOCAL_SRC_FILES  := func.c

LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog   
LOCAL_ARM_MODE := arm
LOCAL_MODULE    := target
LOCAL_SRC_FILES := func.c 
LOCAL_C_INCLUDES := $(LOCAL_PATH) 

include $(BUILD_SHARED_LIBRARY)