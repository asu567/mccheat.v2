TARGET := iphone:clang:latest:15.0
ARCHS  := arm64
include $(THEOS)/makefiles/common.mk
LIBRARY_NAME = MCHeat
MCHeat_FILES = MCHeat.xm
MCHeat_CFLAGS = -fobjc-arc
MCHeat_LDFLAGS = -undefined dynamic_lookup
MCHeat_FRAMEWORKS = UIKit Foundation
include $(THEOS_MAKE_PATH)/library.mk
