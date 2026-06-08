// MqttHashHook.x
// Hook CommonCrypto hash 函数，找 MQTT 凭据生成位置

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <substrate.h>
#include <CommonCrypto/CommonDigest.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// ============================================
// MARK: - 日志管理器
// ============================================

@interface MqttHashLogManager : NSObject
@property (nonatomic, strong) NSMutableArray *logs;
@property (nonatomic, copy) void (^onNewLog)(NSString *log);
+ (instancetype)sharedInstance;
- (void)addLog:(NSString *)log;
@end

@implementation MqttHashLogManager

static MqttHashLogManager *_instance = nil;

+ (instancetype)sharedInstance {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _instance = [[MqttHashLogManager alloc] init];
        _instance.logs = [NSMutableArray array];
    });
    return _instance;
}

- (void)addLog:(NSString *)log {
    @synchronized (self.logs) {
        [self.logs addObject:log];
        if (self.logs.count > 500) {
            [self.logs removeObjectAtIndex:0];
        }
    }
    if (self.onNewLog) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.onNewLog(log);
        });
    }
    NSLog(@"%@", log);
}

@end

// ============================================
// MARK: - 日志查看控制器
// ============================================

@interface MqttHashLogViewController : UITableViewController
@property (nonatomic, strong) NSArray *logs;
@end

@implementation MqttHashLogViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"MQTT Hash Hook";
    self.view.backgroundColor = [UIColor blackColor];
    self.tableView.separatorStyle = UITableViewCellSeparatorStyleNone;
    
    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"关闭"
                                                                             style:UIBarButtonItemStylePlain
                                                                            target:self
                                                                            action:@selector(close)];
    
    self.navigationItem.rightBarButtonItems = @[
        [[UIBarButtonItem alloc] initWithTitle:@"清空"
                                         style:UIBarButtonItemStylePlain
                                        target:self
                                        action:@selector(clearLogs)],
        [[UIBarButtonItem alloc] initWithTitle:@"导出"
                                         style:UIBarButtonItemStylePlain
                                        target:self
                                        action:@selector(shareLogs)]
    ];
    
    @synchronized ([MqttHashLogManager sharedInstance].logs) {
        self.logs = [[MqttHashLogManager sharedInstance].logs copy];
    }
    
    __weak typeof(self) weakSelf = self;
    [MqttHashLogManager sharedInstance].onNewLog = ^(NSString *log) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (strongSelf) {
            @synchronized ([MqttHashLogManager sharedInstance].logs) {
                strongSelf.logs = [[MqttHashLogManager sharedInstance].logs copy];
            }
            [strongSelf.tableView reloadData];
        }
    };
}

- (void)close {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)clearLogs {
    @synchronized ([MqttHashLogManager sharedInstance].logs) {
        [[MqttHashLogManager sharedInstance].logs removeAllObjects];
        self.logs = @[];
    }
    [self.tableView reloadData];
}

- (void)shareLogs {
    @synchronized ([MqttHashLogManager sharedInstance].logs) {
        NSString *allLogs = [[MqttHashLogManager sharedInstance].logs componentsJoinedByString:@"\n"];
        
        NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
        fmt.dateFormat = @"yyyyMMdd_HHmmss";
        NSString *timeStr = [fmt stringFromDate:[NSDate date]];
        NSString *fileName = [NSString stringWithFormat:@"MQTT_Hash_%@.txt", timeStr];
        NSString *tempPath = [NSTemporaryDirectory() stringByAppendingPathComponent:fileName];
        [allLogs writeToFile:tempPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        
        NSURL *fileURL = [NSURL fileURLWithPath:tempPath];
        UIActivityViewController *activityVC = [[UIActivityViewController alloc]
            initWithActivityItems:@[fileURL]
            applicationActivities:nil];
        
        if (UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad) {
            activityVC.popoverPresentationController.sourceView = self.view;
        }
        
        [self presentViewController:activityVC animated:YES completion:nil];
    }
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.logs.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    cell.textLabel.numberOfLines = 0;
    cell.textLabel.font = [UIFont fontWithName:@"Menlo" size:10];
    cell.textLabel.textColor = [UIColor whiteColor];
    cell.backgroundColor = [UIColor blackColor];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    
    NSString *log = self.logs[indexPath.row];
    cell.textLabel.text = log;
    
    if ([log containsString:@"✅ MATCH"]) {
        cell.textLabel.textColor = [UIColor systemGreenColor];
        cell.backgroundColor = [[UIColor systemGreenColor] colorWithAlphaComponent:0.2];
    } else if ([log containsString:@"[MD5]"]) {
        cell.textLabel.textColor = [UIColor systemBlueColor];
    } else if ([log containsString:@"[SHA256]"]) {
        cell.textLabel.textColor = [UIColor systemPurpleColor];
    } else if ([log containsString:@"[SHA1]"]) {
        cell.textLabel.textColor = [UIColor systemOrangeColor];
    }
    
    return cell;
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    return UITableViewAutomaticDimension;
}

@end

// ============================================
// MARK: - 悬浮按钮
// ============================================

@interface MqttHashFloatingButton : UIView
@property (nonatomic, strong) UIView *capsule;
@property (nonatomic, strong) UILabel *statusLabel;
+ (instancetype)shared;
- (void)installIfNeeded;
- (void)updateStatus:(NSString *)status;
@end

@implementation MqttHashFloatingButton

static MqttHashFloatingButton *_shared = nil;

+ (instancetype)shared {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _shared = [MqttHashFloatingButton new];
    });
    return _shared;
}

- (UIWindow *)activeWindow {
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (![scene isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)scene;
            if (ws.activationState != UISceneActivationStateForegroundActive) continue;
            for (UIWindow *w in ws.windows) if (w.isKeyWindow) return w;
            if (ws.windows.count) return ws.windows.firstObject;
        }
    }
    return nil;
}

- (void)installIfNeeded {
    if (self.capsule) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = [self activeWindow];
        if (!window) return;
        
        CGFloat screenW = window.bounds.size.width;
        CGFloat capsuleW = 120;
        CGFloat capsuleH = 36;
        
        CGFloat capsuleY = 52;
        CGFloat capsuleX = screenW - capsuleW - 12;
        
        UIView *c = [[UIView alloc] initWithFrame:CGRectMake(capsuleX, capsuleY, capsuleW, capsuleH)];
        c.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.8];
        c.layer.cornerRadius = capsuleH / 2;
        c.layer.masksToBounds = YES;
        c.layer.borderWidth = 1;
        c.layer.borderColor = [[UIColor systemGreenColor] colorWithAlphaComponent:0.6].CGColor;
        
        UILabel *icon = [[UILabel alloc] initWithFrame:CGRectMake(8, 0, 20, capsuleH)];
        icon.text = @"🔐";
        icon.font = [UIFont systemFontOfSize:14];
        [c addSubview:icon];
        
        _statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(28, 0, capsuleW - 36, capsuleH)];
        _statusLabel.text = @"等待中";
        _statusLabel.textColor = [UIColor systemGreenColor];
        _statusLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightMedium];
        [c addSubview:_statusLabel];
        
        UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(openLog)];
        [c addGestureRecognizer:tap];
        
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
        [c addGestureRecognizer:pan];
        
        [window addSubview:c];
        self.capsule = c;
    });
}

- (void)updateStatus:(NSString *)status {
    dispatch_async(dispatch_get_main_queue(), ^{
        self->_statusLabel.text = status;
    });
}

- (void)handlePan:(UIPanGestureRecognizer *)gesture {
    UIView *c = gesture.view;
    UIWindow *window = [self activeWindow];
    if (!window) return;
    
    CGPoint translation = [gesture translationInView:window];
    CGFloat halfW = c.bounds.size.width / 2;
    CGFloat halfH = c.bounds.size.height / 2;
    CGFloat newX = c.center.x + translation.x;
    CGFloat newY = c.center.y + translation.y;
    
    newX = MAX(halfW, MIN(window.bounds.size.width - halfW, newX));
    newY = MAX(halfH, MIN(window.bounds.size.height - halfH, newY));
    
    c.center = CGPointMake(newX, newY);
    [gesture setTranslation:CGPointZero inView:window];
}

- (void)openLog {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = [self activeWindow];
        UIViewController *root = window.rootViewController;
        while (root.presentedViewController) root = root.presentedViewController;
        
        MqttHashLogViewController *vc = [[MqttHashLogViewController alloc] init];
        UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
        nav.navigationBar.barStyle = UIBarStyleBlack;
        nav.navigationBar.tintColor = [UIColor whiteColor];
        nav.modalPresentationStyle = UIModalPresentationPageSheet;
        [root presentViewController:nav animated:YES completion:nil];
    });
}

@end

// ============================================
// MARK: - 检查 hash 结果
// ============================================

static NSString *kKnownUsername = @"d4a107b765f38550d13a24b54fdcdecf";
static NSString *kKnownPassword = @"7c039ddfbdad50f3d0caf974fbcd5a5f";
static NSUInteger g_hashCount = 0;

static void checkHashResult(const char *type, const void *inputBytes, CC_LONG inputLen, const uint8_t *digest, size_t digestLen) {
    g_hashCount++;
    
    // 每 100 次更新一次计数
    if (g_hashCount % 100 == 0) {
        [[MqttHashFloatingButton shared] updateStatus:[NSString stringWithFormat:@"%lu", (unsigned long)g_hashCount]];
    }
    
    NSMutableString *hexString = [NSMutableString string];
    for (size_t i = 0; i < digestLen; i++) {
        [hexString appendFormat:@"%02x", digest[i]];
    }
    
    BOOL matchUsername = [hexString isEqualToString:kKnownUsername];
    BOOL matchPassword = [hexString isEqualToString:kKnownPassword];
    
    if (matchUsername || matchPassword) {
        NSString *matchType = matchUsername ? @"Username" : @"Password";
        
        NSData *inputNSData = [NSData dataWithBytes:inputBytes length:inputLen];
        NSString *inputStr = [[NSString alloc] initWithData:inputNSData encoding:NSUTF8StringEncoding];
        if (!inputStr) inputStr = [inputNSData description];
        
        [[MqttHashLogManager sharedInstance] addLog:@"========================================"];
        [[MqttHashLogManager sharedInstance] addLog:[NSString stringWithFormat:@"[MQTT HASH] ✅ MATCH! %s = %@ (%@)", type, hexString, matchType]];
        [[MqttHashLogManager sharedInstance] addLog:[NSString stringWithFormat:@"[MQTT HASH] 输入: %@ (长度:%u)", inputStr, inputLen]];
        [[MqttHashLogManager sharedInstance] addLog:@"[MQTT HASH] 堆栈:"];
        
        NSArray *callStack = [NSThread callStackSymbols];
        for (NSString *symbol in callStack) {
            if ([symbol containsString:@"LingLingBang"] || [symbol containsString:@"CYUnified"] || [symbol containsString:@"Botai"] || [symbol containsString:@"MQTT"] || [symbol containsString:@"Keyless"]) {
                [[MqttHashLogManager sharedInstance] addLog:[NSString stringWithFormat:@"[MQTT HASH]   %@", symbol]];
            }
        }
        [[MqttHashLogManager sharedInstance] addLog:@"========================================"];
        
        [[MqttHashFloatingButton shared] updateStatus:@"✅ 找到!"];
    }
}

// ============================================
// MARK: - Hook CommonCrypto
// ============================================

extern unsigned char *CC_MD5(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *(*orig_CC_MD5)(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *hook_CC_MD5(const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *result = orig_CC_MD5(data, len, md);
    if (result) checkHashResult("MD5", data, len, result, CC_MD5_DIGEST_LENGTH);
    return result;
}

extern unsigned char *CC_SHA256(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *(*orig_CC_SHA256)(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *hook_CC_SHA256(const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *result = orig_CC_SHA256(data, len, md);
    if (result) {
        checkHashResult("SHA256", data, len, result, CC_SHA256_DIGEST_LENGTH);
        checkHashResult("SHA256[:16]", data, len, result, 16);
    }
    return result;
}

extern unsigned char *CC_SHA1(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *(*orig_CC_SHA1)(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *hook_CC_SHA1(const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *result = orig_CC_SHA1(data, len, md);
    if (result) checkHashResult("SHA1[:16]", data, len, result, 16);
    return result;
}

// ============================================
// MARK: - 显示 HUD
// ============================================

static void showHUDIfNeeded(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [[MqttHashFloatingButton shared] installIfNeeded];
        [[MqttHashFloatingButton shared] updateStatus:@"已启动"];
    });
}

// ============================================
// MARK: - 初始化
// ============================================

%ctor {
    @autoreleasepool {
        @try {
            // Hook CommonCrypto
            MSHookFunction(CC_MD5, hook_CC_MD5, (void **)&orig_CC_MD5);
            MSHookFunction(CC_SHA256, hook_CC_SHA256, (void **)&orig_CC_SHA256);
            MSHookFunction(CC_SHA1, hook_CC_SHA1, (void **)&orig_CC_SHA1);
            
            NSLog(@"[MQTT HASH HOOK] 🔐 Tweak 已加载！");
            [[MqttHashLogManager sharedInstance] addLog:@"[MQTT HASH HOOK] 🔐 已加载，监控 MD5/SHA256/SHA1"];
            
            // 延迟显示悬浮按钮
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                showHUDIfNeeded();
            });
        } @catch (NSException *exception) {
            NSLog(@"[MQTT HASH HOOK] ctor exception: %@ %@", exception.name, exception.reason);
        }
    }
}

#pragma clang diagnostic pop
