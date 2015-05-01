LOCAL_PATH := $(call my-dir)  

#
# inject_static module
#
include $(CLEAR_VARS)
LOCAL_MODULE := inject_static
# Source Files
LOCAL_SRC_FILES := inject.c \
                   hook.c
                   
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH) \
                           $(LOCAL_PATH)/. 
                   
# Header Files
LOCAL_C_INCLUDES := $(LOCAL_PATH) \
                    $(LOCAL_PATH)/. 

LOCAL_EXPORT_LDLIBS := -L$(SYSROOT)/usr/lib -llog 
include $(BUILD_STATIC_LIBRARY)
