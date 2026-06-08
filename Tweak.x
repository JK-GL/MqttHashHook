// MqttHashHook.x
// Hook CommonCrypto hash 函数，找 MQTT 凭据生成位置

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <substrate.h>

// 抑制 CC_MD5 弃用警告
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// 已知的 MQTT 凭据
static NSString *kKnownUsername = @"d4a107b765f38550d13a24b54fdcdecf";
static NSString *kKnownPassword = @"7c039ddfbdad50f3d0caf974fbcd5a5f";

static NSMutableString *g_logBuffer = nil;

static void logMsg(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    
    @synchronized (g_logBuffer) {
        [g_logBuffer appendString:msg];
        [g_logBuffer appendString:@"\n"];
        if (g_logBuffer.length > 100000) {
            [g_logBuffer deleteCharactersInRange:NSMakeRange(0, g_logBuffer.length - 50000)];
        }
    }
    NSLog(@"%@", msg);
}

// ============================================
// MARK: - 检查 hash 结果
// ============================================

static void checkHashResult(const char *type, const uint8_t *digest, size_t digestLen) {
    NSMutableString *hexString = [NSMutableString string];
    for (size_t i = 0; i < digestLen; i++) {
        [hexString appendFormat:@"%02x", digest[i]];
    }
    
    BOOL matchUsername = [hexString isEqualToString:kKnownUsername];
    BOOL matchPassword = [hexString isEqualToString:kKnownPassword];
    
    if (matchUsername || matchPassword) {
        NSString *matchType = matchUsername ? @"Username" : @"Password";
        logMsg(@"[MQTT HASH] ✅ MATCH! %s = %@ (%@)", type, hexString, matchType);
        
        NSArray *callStack = [NSThread callStackSymbols];
        logMsg(@"[MQTT HASH] 堆栈:");
        for (NSString *symbol in callStack) {
            if ([symbol containsString:@"LingLingBang"] || [symbol containsString:@"CYUnified"] || [symbol containsString:@"Botai"] || [symbol containsString:@"MQTT"]) {
                logMsg(@"[MQTT HASH]   %@", symbol);
            }
        }
    }
}

// ============================================
// MARK: - Hook CC_MD5
// ============================================

extern unsigned char *CC_MD5(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *(*orig_CC_MD5)(const void *data, CC_LONG len, unsigned char *md);

static unsigned char *hook_CC_MD5(const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *result = orig_CC_MD5(data, len, md);
    
    if (len > 0 && len < 500) {
        NSData *inputData = [NSData dataWithBytes:data length:len];
        NSString *inputStr = [[NSString alloc] initWithData:inputData encoding:NSUTF8StringEncoding];
        if (inputStr && inputStr.length > 0) {
            logMsg(@"[MD5] len=%d input=%@", len, inputStr);
        }
    }
    
    checkHashResult("MD5", result, CC_MD5_DIGEST_LENGTH);
    return result;
}

// ============================================
// MARK: - Hook CC_SHA256
// ============================================

extern unsigned char *CC_SHA256(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *(*orig_CC_SHA256)(const void *data, CC_LONG len, unsigned char *md);

static unsigned char *hook_CC_SHA256(const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *result = orig_CC_SHA256(data, len, md);
    
    if (len > 0 && len < 500) {
        NSData *inputData = [NSData dataWithBytes:data length:len];
        NSString *inputStr = [[NSString alloc] initWithData:inputData encoding:NSUTF8StringEncoding];
        if (inputStr && inputStr.length > 0) {
            logMsg(@"[SHA256] len=%d input=%@", len, inputStr);
        }
    }
    
    // 检查完整 32 字节
    checkHashResult("SHA256", result, CC_SHA256_DIGEST_LENGTH);
    
    // 检查前 16 字节（截断到 32 位 hex）
    checkHashResult("SHA256[:16]", result, 16);
    
    return result;
}

// ============================================
// MARK: - Hook CC_SHA1
// ============================================

extern unsigned char *CC_SHA1(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *(*orig_CC_SHA1)(const void *data, CC_LONG len, unsigned char *md);

static unsigned char *hook_CC_SHA1(const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *result = orig_CC_SHA1(data, len, md);
    
    if (len > 0 && len < 500) {
        NSData *inputData = [NSData dataWithBytes:data length:len];
        NSString *inputStr = [[NSString alloc] initWithData:inputData encoding:NSUTF8StringEncoding];
        if (inputStr && inputStr.length > 0) {
            logMsg(@"[SHA1] len=%d input=%@", len, inputStr);
        }
    }
    
    checkHashResult("SHA1[:16]", result, 16);
    return result;
}

// ============================================
// MARK: - 导出日志（通过 NSFileManager）
// ============================================

static void exportLog(void) {
    NSString *logPath = @"/var/mobile/Documents/MQTT_Hash_Log.txt";
    @synchronized (g_logBuffer) {
        [g_logBuffer writeToFile:logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    logMsg(@"[EXPORT] 日志已导出到: %@", logPath);
}

// ============================================
// MARK: - 初始化
// ============================================

%ctor {
    @autoreleasepool {
        g_logBuffer = [NSMutableString string];
        
        // Hook CommonCrypto
        MSHookFunction(CC_MD5, hook_CC_MD5, (void **)&orig_CC_MD5);
        MSHookFunction(CC_SHA256, hook_CC_SHA256, (void **)&orig_CC_SHA256);
        MSHookFunction(CC_SHA1, hook_CC_SHA1, (void **)&orig_CC_SHA1);
        
        logMsg(@"[MQTT HASH HOOK] 🔐 Tweak 已加载，开始监控 hash 函数...");
        
        // 每 30 秒自动导出日志
        dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
        dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW), 30 * NSEC_PER_SEC, 5 * NSEC_PER_SEC);
        dispatch_source_set_event_handler(timer, ^{
            exportLog();
        });
        dispatch_resume(timer);
    }
}

#pragma clang diagnostic pop
