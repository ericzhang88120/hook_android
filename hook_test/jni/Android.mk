#test 
LOCAL_PATH:=$(call my-dir)
$(call import-add-path,C:\Users\Administrator\Desktop\hook_helloworld\hool_helloworld\hook_test\jni)
#=========hook function============

include $(CLEAR_VARS)
LOCAL_MODULE := test

LOCAL_SRC_FILES:=main.c

LOCAL_STATIC_LIBRARIES := inject_static

include $(BUILD_EXECUTABLE)

$(call import-module, src)