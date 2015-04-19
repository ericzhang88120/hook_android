#test 
LOCAL_PATH:=$(call my-dir)
$(call import-add-path,E:/hook_test/jni)
#=========hook function============

include $(CLEAR_VARS)
LOCAL_MODULE := test

LOCAL_SRC_FILES:=main.cc

LOCAL_STATIC_LIBRARIES := util

include $(BUILD_EXECUTABLE)

$(call import-module, src)