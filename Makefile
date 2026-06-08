ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MqttHashHook

MqttHashHook_FILES = Tweak.x
MqttHashHook_CFLAGS = -fobjc-arc
MqttHashHook_FRAMEWORKS = UIKit Foundation

include $(THEOS_MAKE_PATH)/tweak.mk
