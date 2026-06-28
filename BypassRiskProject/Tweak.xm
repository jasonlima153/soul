#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <Security/Security.h>
#ifndef CF_BRIDGED_TYPE
#define CF_BRIDGED_TYPE(TYPE)
#endif
#if __has_include(<Security/SecCode.h>)
#  import <Security/SecCode.h>
#  import <Security/SecRequirement.h>
#else
// Forward declarations for private Security code-signing types
typedef uint32_t SecCSFlags;
typedef struct CF_BRIDGED_TYPE(id) __SecCode *SecCodeRef;
typedef struct CF_BRIDGED_TYPE(id) __SecRequirement *SecRequirementRef;
#endif
#import "fishhook.h"

// ==========================================
// 1. 配置信息与全局缓存
// ==========================================
static NSString *const kOfficialBundleID = @"com.soulapp.cn";
static NSString *const kOfficialTeamID   = @"M8FGKU3T4J";

// ==========================================
// 2. 核心拦截模块：Security 签名框架断路
// ==========================================
typedef OSStatus (*SecCodeCopySelf_t)(SecCSFlags flags, SecCodeRef *self);
static SecCodeCopySelf_t orig_SecCodeCopySelf = NULL;

OSStatus my_SecCodeCopySelf(SecCSFlags flags, SecCodeRef *self) {
    return errSecSuccess;
}

typedef OSStatus (*SecCodeCheckValidity_t)(SecCodeRef code, SecCSFlags flags, SecRequirementRef requirement);
static SecCodeCheckValidity_t orig_SecCodeCheckValidity = NULL;

OSStatus my_SecCodeCheckValidity(SecCodeRef code, SecCSFlags flags, SecRequirementRef requirement) {
    return errSecSuccess;
}

// ==========================================
// 3. 核心拦截模块：动态库加载异步回调屏蔽
// ==========================================
typedef void (*dyld_image_callback)(const struct mach_header* mh, intptr_t vmaddr_slide);
typedef void (*_dyld_register_func_for_add_image_t)(dyld_image_callback func);
static _dyld_register_func_for_add_image_t orig_dyld_register_func_for_add_image = NULL;

static dyld_image_callback g_risk_plugin_callback = NULL;

// Plain C callback wrapper (avoids C++11 lambda which fails under ObjC mode)
static void shadow_callback_func(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if (mh != NULL) {
        const char* image_name = _dyld_get_image_name(0);
        if (image_name && (strstr(image_name, "BypassRiskPlugin") || strstr(image_name, ".app/Frameworks/"))) {
            return;
        }
    }
    if (g_risk_plugin_callback) {
        g_risk_plugin_callback(mh, vmaddr_slide);
    }
}

void my_dyld_register_func_for_add_image(dyld_image_callback func) {
    g_risk_plugin_callback = func;
    orig_dyld_register_func_for_add_image(shadow_callback_func);
}

// ==========================================
// 4. 核心拦截模块：底层文件系统检测重定向
// ==========================================
typedef int (*open_t)(const char *path, int oflag, ...);
static open_t orig_open = NULL;

int my_open(const char *path, int oflag, ...) {
    va_list args;
    va_start(args, oflag);
    mode_t mode = va_arg(args, int);
    va_end(args);

    if (path != NULL) {
        if (strstr(path, ".app/Soul_New") && !strstr(path, ".backup")) {
            NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
            NSString *backupPath = [bundlePath stringByAppendingPathComponent:@"Soul_New.backup"];
            return orig_open([backupPath UTF8String], oflag, mode);
        }
    }
    return orig_open(path, oflag, mode);
}

// ==========================================
// 5. 应用层 Hook：Bundle 基础数据与设备指纹洗白
// ==========================================
void initClassHooks() {
    // 1. Hook [NSBundle bundleIdentifier]
    Method origBundleID = class_getInstanceMethod([NSBundle class], @selector(bundleIdentifier));
    IMP mockBundleID = imp_implementationWithBlock(^NSString* (id self) {
        return kOfficialBundleID;
    });
    method_setImplementation(origBundleID, mockBundleID);

    // 2. Hook [NSBundle infoDictionary]
    Method origInfo = class_getInstanceMethod([NSBundle class], @selector(infoDictionary));
    // Save original IMP before replacing to avoid recursive call
    IMP origInfoIMP = method_getImplementation(origInfo);
    IMP mockInfo = imp_implementationWithBlock(^NSDictionary* (id self) {
        NSDictionary *origDict = ((NSDictionary* (*)(id, SEL))origInfoIMP)(self, @selector(infoDictionary));
        NSMutableDictionary *mockDict = [origDict mutableCopy];
        mockDict[@"CFBundleIdentifier"] = kOfficialBundleID;
        mockDict[@"AppIdentifierPrefix"] = kOfficialTeamID;
        return [mockDict copy];
    });
    method_setImplementation(origInfo, mockInfo);

    // 3. Hook [UIDevice identifierForVendor] 生成逻辑自洽的虚拟指纹
    Method origIdfv = class_getInstanceMethod([UIDevice class], @selector(identifierForVendor));
    IMP mockIdfv = imp_implementationWithBlock(^NSUUID* (id self) {
        NSString *cachedIdfv = [[NSUserDefaults standardUserDefaults] stringForKey:@"v_device_idfv"];
        if (!cachedIdfv) {
            cachedIdfv = [[NSUUID UUID] UUIDString];
            [[NSUserDefaults standardUserDefaults] setObject:cachedIdfv forKey:@"v_device_idfv"];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
        return [[NSUUID alloc] initWithUUIDString:cachedIdfv];
    });
    method_setImplementation(origIdfv, mockIdfv);
}

// ==========================================
// 6. 构造函数初始化（最高执行优先级）
// ==========================================
__attribute__((constructor)) static void init_bypass_gateway() {
    @autoreleasepool {
        rebind_symbols((struct rebinding[4]){
            {"SecCodeCopySelf", (void *)my_SecCodeCopySelf, (void **)&orig_SecCodeCopySelf},
            {"SecCodeCheckValidity", (void *)my_SecCodeCheckValidity, (void **)&orig_SecCodeCheckValidity},
            {"_dyld_register_func_for_add_image", (void *)my_dyld_register_func_for_add_image, (void **)&orig_dyld_register_func_for_add_image},
            {"open", (void *)my_open, (void **)&orig_open}
        }, 4);

        initClassHooks();

        NSLog(@"[BypassPlugin] Industrial-grade risk control bypass gateway ready.");
    }
}