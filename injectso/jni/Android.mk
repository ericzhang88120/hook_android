LOCAL_PATH := $(call my-dir)  
$(call import-add-path,C:\Users\Administrator\Desktop\hook_helloworld\hool_helloworld\injectso\jni)
  
include $(CLEAR_VARS)  
  
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog   
LOCAL_ARM_MODE := arm  
LOCAL_MODULE    := hello  
LOCAL_SRC_FILES := hello.c  
LOCAL_STATIC_LIBRARIES := inject_static
include $(BUILD_SHARED_LIBRARY)

$(call import-module, include)