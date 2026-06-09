// MqttHashHook.x
// Hook CommonCrypto hash 函数，找 MQTT 凭据生成位置

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <substrate.h>
#include <CommonCrypto/CommonDigest.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// ============================================
// 已知凭据
// ============================================

static NSString *kKnownUsername = @"d4a107b765f38550d13a24b54fdcdecf";
static NSString *kKnownPassword = @"7c039ddfbdad50f3d0caf974fbcd5a5f";

static NSMutableString *g_logBuffer = nil;
static NSUInteger g_hashCount = 0;
static BOOL g_found = NO;

static void flushLog(void) {
    if (!g_logBuffer || g_logBuffer.length == 0) return;
    @synchronized (g_logBuffer) {
        [g_logBuffer writeToFile:@"/var/mobile/Documents/MqttHashHook.txt"
                      atomically:YES
                        encoding:NSUTF8StringEncoding
                           error:nil];
    }
}

static void logMsg(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    
    @synchronized (g_logBuffer) {
        [g_logBuffer appendString:msg];
        [g_logBuffer appendString:@"\n"];
        if (g_logBuffer.length > 200000) {
            [g_logBuffer deleteCharactersInRange:NSMakeRange(0, g_logBuffer.length - 100000)];
        }
    }
    NSLog(@"[MqttHashHook] %@", msg);
}

// ============================================
// 检查 hash 输出
// ============================================

static void checkDigest(const char *type, const void *input, CC_LONG inputLen, const uint8_t *digest, size_t digestLen) {
    g_hashCount++;
    
    if (g_hashCount % 500 == 0) {
        logMsg(@"[COUNT] 已监控 %lu 次 hash", (unsigned long)g_hashCount);
        flushLog();
    }
    
    // 转 hex
    NSMutableString *hex = [NSMutableString stringWithCapacity:digestLen * 2];
    for (size_t i = 0; i < digestLen; i++) {
        [hex appendFormat:@"%02x", digest[i]];
    }
    
    BOOL match = NO;
    NSString *matchType = nil;
    if ([hex isEqualToString:kKnownUsername]) { match = YES; matchType = @"Username"; }
    if ([hex isEqualToString:kKnownPassword]) { match = YES; matchType = @"Password"; }
    
    if (match) {
        g_found = YES;
        
        NSData *data = [NSData dataWithBytes:input length:inputLen];
        NSString *inputStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (!inputStr) inputStr = [data description];
        
        logMsg(@"");
        logMsg(@"========================================");
        logMsg(@"✅ 找到了！%s 输出匹配 %@", type, matchType);
        logMsg(@"   Hash: %@", hex);
        logMsg(@"   输入: %@", inputStr);
        logMsg(@"   输入长度: %u", inputLen);
        logMsg(@"========================================");
        
        NSArray *stack = [NSThread callStackSymbols];
        logMsg(@"堆栈:");
        for (NSString *s in stack) {
            if ([s containsString:@"LingLingBang"] || [s containsString:@"CYUnified"] || [s containsString:@"Botai"] || [s containsString:@"MQTT"] || [s containsString:@"Keyless"] || [s containsString:@"BaoJun"]) {
                logMsg(@"  %@", s);
            }
        }
        logMsg(@"");
        flushLog();
    }
}

// ============================================
// Hook CC_MD5
// ============================================

extern unsigned char *CC_MD5(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *(*orig_CC_MD5)(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *hook_CC_MD5(const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *result = orig_CC_MD5(data, len, md);
    if (result && len > 0) checkDigest("MD5", data, len, result, CC_MD5_DIGEST_LENGTH);
    return result;
}

// ============================================
// Hook CC_SHA256
// ============================================

extern unsigned char *CC_SHA256(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *(*orig_CC_SHA256)(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *hook_CC_SHA256(const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *result = orig_CC_SHA256(data, len, md);
    if (result && len > 0) {
        checkDigest("SHA256", data, len, result, CC_SHA256_DIGEST_LENGTH);
        checkDigest("SHA256[:16]", data, len, result, 16);
    }
    return result;
}

// ============================================
// Hook CC_SHA1
// ============================================

extern unsigned char *CC_SHA1(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *(*orig_CC_SHA1)(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *hook_CC_SHA1(const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *result = orig_CC_SHA1(data, len, md);
    if (result && len > 0) checkDigest("SHA1[:16]", data, len, result, 16);
    return result;
}

// ============================================
// 初始化
// ============================================

%ctor {
    @autoreleasepool {
        g_logBuffer = [NSMutableString string];
        
        // 标记文件
        [@"LOADED" writeToFile:@"/var/mobile/Documents/MqttHashHook_loaded.txt"
                    atomically:YES encoding:NSUTF8StringEncoding error:nil];
        
        logMsg(@"[INIT] MqttHashHook 已加载 PID=%d Process=%@", getpid(), [NSProcessInfo processInfo].processName);
        
        MSHookFunction(CC_MD5, hook_CC_MD5, (void **)&orig_CC_MD5);
        MSHookFunction(CC_SHA256, hook_CC_SHA256, (void **)&orig_CC_SHA256);
        MSHookFunction(CC_SHA1, hook_CC_SHA1, (void **)&orig_CC_SHA1);
        
        logMsg(@"[INIT] Hook 已安装");
        
        // 定时写文件
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            while (YES) {
                sleep(30);
                flushLog();
            }
        });
        
        // 延迟安装悬浮按钮
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIWindow *keyWindow = nil;
            if (@available(iOS 13.0, *)) {
                for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                    if (![scene isKindOfClass:[UIWindowScene class]]) continue;
                    for (UIWindow *w in ((UIWindowScene *)scene).windows) {
                        if (w.isKeyWindow) { keyWindow = w; break; }
                    }
                    if (keyWindow) break;
                }
            }
            if (!keyWindow) return;
            
            CGFloat sw = keyWindow.bounds.size.width;
            CGFloat capsuleW = 140;
            CGFloat capsuleH = 32;
            
            UIView *c = [[UIView alloc] initWithFrame:CGRectMake(sw - capsuleW - 12, 52, capsuleW, capsuleH)];
            c.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.85];
            c.layer.cornerRadius = capsuleH / 2;
            c.clipsToBounds = YES;
            c.layer.borderWidth = 1;
            c.layer.borderColor = [UIColor systemGreenColor].CGColor;
            
            UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(8, 0, capsuleW - 16, capsuleH)];
            label.text = @"🔐 0";
            label.textColor = [UIColor systemGreenColor];
            label.font = [UIFont systemFontOfSize:11 weight:UIFontWeightMedium];
            label.tag = 999;
            [c addSubview:label];
            
            // 点击导出
            [c addGestureRecognizer:[[UITapGestureRecognizer alloc] initWithTarget:c action:@selector(superview)]];
            
            [keyWindow addSubview:c];
            
            // 定时更新计数
            dispatch_async(dispatch_get_global_queue(0, 0), ^{
                while (YES) {
                    sleep(3);
                    dispatch_async(dispatch_get_main_queue(), ^{
                        UILabel *lb = [c viewWithTag:999];
                        if (lb) {
                            if (g_found) {
                                lb.text = [NSString stringWithFormat:@"✅ %lu", (unsigned long)g_hashCount];
                                c.layer.borderColor = [UIColor systemOrangeColor].CGColor;
                            } else {
                                lb.text = [NSString stringWithFormat:@"🔐 %lu", (unsigned long)g_hashCount];
                            }
                        }
                    });
                }
            });
        });
    }
}

#pragma clang diagnostic pop
