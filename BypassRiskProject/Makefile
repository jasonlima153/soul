TARGET := iphone:clang:latest:15.0
ARCHS := arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = BypassRiskPlugin

BypassRiskPlugin_FILES = Tweak.xm fishhook.c
BypassRiskPlugin_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
BypassRiskPlugin_FRAMEWORKS = Foundation UIKit Security

include $(THEOS_MAKE_PATH)/tweak.mk