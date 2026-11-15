// MCHeat — Minecraft Bedrock (iOS) patcher
// TrollFools / TrollStore 用。ellekit を実行時解決するため substrate 不要。
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <substrate.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/vm_map.h>
#include <libkern/OSCacheControl.h>

// ===== 署名・パッチ定義（バージョン更新時はここだけ直す） =====
#define SIG_LOCAL_TICK    "?? ?? ?? A9 ?? ?? ?? F9"
#define SIG_CAN_FLY       "?? ?? ?? 52 ?? ?? ?? 72"
#define SIG_IS_FLYING     "?? ?? ?? 39 ?? ?? ?? 39"
#define SIG_GET_LEVEL     "?? ?? ?? 94 ?? ?? ?? B4"
#define SIG_ACTOR_LIST    "?? ?? ?? A9 ?? ?? ?? 91"
#define SIG_DISTANCE      "?? ?? ?? 1E ?? ?? ?? 1E"
#define SIG_ATTACK        "?? ?? ?? A9 ?? ?? ?? 94"
#define PATCH_FLY_TRUE    "20 00 80 52 C0 03 5F D6"   // mov w0,#1 ; ret
#define PATCH_BREAK_SIG   "?? ?? ?? 1E ?? ?? ?? 1E"
#define PATCH_BREAK       "00 00 80 3F"                 // 破壊時間の除数 1.0f
#define PATCH_REACH_SIG   "?? ?? ?? 1E ?? ?? ?? 1E"
#define PATCH_REACH       "00 00 C0 40"                 // リーチ 6.0f

typedef void (*HookFn)(void *, void *, void **);

static uint8_t *g_text; static size_t g_len;
static NSMutableDictionary *g_orig, *g_addr;
static void *g_local; static int g_tick;
static BOOL g_ka; static float g_radius = 4.5f;
static HookFn p_hook;

static void (*o_tick)(void *);
static void *(*o_getLevel)(void *);
static void *(*o_actorList)(void *, void *);
static float (*o_dist)(void *, void *);
static void (*o_attack)(void *, void *);

// ===== Core =====
@interface Core : NSObject
+ (BOOL)prepare;
+ (BOOL)patchSig:(const char *)sig bytes:(const char *)hex key:(NSString *)key;
+ (BOOL)revertKey:(NSString *)key;
+ (BOOL)installHooks;
+ (void)setFly:(BOOL)on;
+ (void)setKillaura:(BOOL)on;
+ (void)setNuker:(BOOL)on;
+ (void)setRadius:(float)r;
@end

@implementation Core

+ (BOOL)prepare {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *n = _dyld_get_image_name(i);
        if (!n || !strstr(n, "Minecraft.app/Minecraft")) continue;
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (h->magic != MH_MAGIC_64) continue;
        uint8_t *c = (uint8_t *)(h + 1);
        for (uint32_t k = 0; k < h->ncmds; k++) {
            struct load_command *lc = (struct load_command *)c;
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *sg = (struct segment_command_64 *)lc;
                if (!strcmp(sg->segname, "__TEXT")) {
                    struct section_64 *s = (struct section_64 *)(sg + 1);
                    for (uint32_t j = 0; j < sg->nsects; j++, s++)
                        if (!strcmp(s->sectname, "__text")) { g_text = (uint8_t *)h + s->offset; g_len = s->size; }
                }
            }
            c += lc->cmdsize;
        }
        if (g_text) break;
    }
    g_orig = [NSMutableDictionary new];
    g_addr = [NSMutableDictionary new];
    return g_text != NULL;
}

static uint8_t *scan(const char *sig) {
    if (!g_text) return NULL;
    uint8_t p[64], m[64]; int n = 0; char b[256]; strlcpy(b, sig, sizeof b);
    for (char *t = strtok(b, " "); t && n < 64; t = strtok(NULL, " ")) {
        if (!strcmp(t, "??")) { p[n] = 0; m[n] = 0; }
        else { p[n] = (uint8_t)strtoul(t, NULL, 16); m[n] = 0xFF; }
        n++;
    }
    for (size_t i = 0; i + n <= g_len; i++) {
        int j = 0; for (; j < n && (g_text[i + j] & m[j]) == p[j]; j++);
        if (j == n) return g_text + i;
    }
    return NULL;
}

static uint8_t *funcStart(uint8_t *hit) {
    static const uint8_t pat[4] = {0xFD, 0x7B, 0x00, 0xA9}, msk[4] = {0xFF, 0xFF, 0xF0, 0xFF};
    for (int i = 0; i < 4096; i++) {
        uint8_t *a = hit - i;
        if (a < g_text + 4) break;
        if ((a[0] & msk[0]) == pat[0] && (a[1] & msk[1]) == pat[1]
            && (a[2] & msk[2]) == pat[2] && (a[3] & msk[3]) == pat[3]) return a;
    }
    return NULL;
}

static void protect(uint8_t *a, size_t l, int prot) {
    uintptr_t pg = (uintptr_t)a & ~0xFFF;
    size_t sp = ((uintptr_t)a + l - pg + 0xFFF) & ~0xFFF;
    vm_protect(mach_task_self(), pg, sp, false, prot);
}

+ (BOOL)patchSig:(const char *)sig bytes:(const char *)hex key:(NSString *)key {
    uint8_t *hit = scan(sig); if (!hit) return NO;
    NSMutableData *d = [NSMutableData new]; char b[128]; strlcpy(b, hex, sizeof b);
    for (char *t = strtok(b, " "); t; t = strtok(NULL, " ")) {
        uint8_t x = (uint8_t)strtoul(t, NULL, 16); [d appendBytes:&x length:1];
    }
    protect(hit, d.length, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    g_orig[key] = [NSData dataWithBytes:hit length:d.length];
    g_addr[key] = [NSValue valueWithPointer:hit];
    memcpy(hit, d.bytes, d.length);
    protect(hit, d.length, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate(hit, d.length);
    return YES;
}

+ (BOOL)revertKey:(NSString *)key {
    NSData *o = g_orig[key]; NSValue *v = g_addr[key]; if (!o) return NO;
    uint8_t *a = v.pointerValue;
    protect(a, o.length, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    memcpy(a, o.bytes, o.length);
    protect(a, o.length, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate(a, o.length);
    return YES;
}

static BOOL resolveHook(void) {
    p_hook = (HookFn)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (p_hook) return YES;
    Dl_info i;
    if (!dladdr((void *)&resolveHook, &i) || !i.dli_fname) return NO;
    char dir[PATH_MAX]; strlcpy(dir, i.dli_fname, sizeof dir);
    char *s = strrchr(dir, '/'); if (!s) return NO; *s = 0;
    const char *c[3] = {"/libellekit.dylib", "/Frameworks/libellekit.dylib", "/../libellekit.dylib"};
    for (int k = 0; k < 3; k++) {
        char p[PATH_MAX]; snprintf(p, sizeof p, "%s%s", dir, c[k]);
        void *h = dlopen(p, RTLD_NOW);
        if (h && (p_hook = (HookFn)dlsym(h, "MSHookFunction"))) return YES;
    }
    return NO;
}

static void hookSig(const char *sig, void *repl, void **orig, const char *tag) {
    if (!p_hook) return;
    uint8_t *h = scan(sig);
    uint8_t *f = h ? funcStart(h) : NULL;
    if (f) p_hook(f, repl, orig);
    else NSLog(@"[MCHeat] hook miss: %s", tag);
}

struct Vec { void **b, **e, **c; };

static void h_tick(void *self) {
    o_tick(self);
    g_local = self;
    if (!g_ka || (++g_tick % 4)) return;
    if (!o_getLevel || !o_actorList || !o_dist || !o_attack) return;
    void *lvl = o_getLevel(self); if (!lvl) return;
    struct Vec v = {0}; o_actorList(lvl, &v);
    for (void **it = v.b; it && it < v.e; it++) {
        void *e = *it; if (!e || e == self) continue;
        if (o_dist(self, e) <= g_radius) o_attack(self, e);
    }
}

+ (BOOL)installHooks {
    resolveHook();
    hookSig(SIG_GET_LEVEL,  (void *)&o_getLevel,  NULL, "getLevel");
    hookSig(SIG_ACTOR_LIST, (void *)&o_actorList, NULL, "actorList");
    hookSig(SIG_DISTANCE,   (void *)&o_dist,      NULL, "distance");
    hookSig(SIG_ATTACK,     (void *)&o_attack,    NULL, "attack");
    hookSig(SIG_LOCAL_TICK, (void *)h_tick, (void **)&o_tick, "tick");
    return o_tick != NULL;
}

+ (void)setFly:(BOOL)on {
    if (on) {
        [self patchSig:SIG_CAN_FLY   bytes:PATCH_FLY_TRUE key:@"fly1"];
        [self patchSig:SIG_IS_FLYING bytes:PATCH_FLY_TRUE key:@"fly2"];
    } else {
        [self revertKey:@"fly1"]; [self revertKey:@"fly2"];
    }
}

+ (void)setKillaura:(BOOL)on { g_ka = on; }
+ (void)setRadius:(float)r { g_radius = r; }

+ (void)setNuker:(BOOL)on {
    if (on) {
        [self patchSig:PATCH_BREAK_SIG bytes:PATCH_BREAK key:@"nuke"];
        [self patchSig:PATCH_REACH_SIG bytes:PATCH_REACH key:@"reach"];
    } else {
        [self revertKey:@"nuke"]; [self revertKey:@"reach"];
    }
}
@end

// ===== Menu =====
@interface Menu : NSObject
+ (instancetype)shared;
- (void)show;
@end

@implementation Menu {
    UIView *_root, *_panel; UILabel *_status; CGPoint _grab;
}

+ (instancetype)shared {
    static Menu *m; static dispatch_once_t t;
    dispatch_once(&t, ^{ m = [Menu new]; });
    return m;
}

- (void)show {
    UIWindow *w = UIApplication.sharedApplication.keyWindow; if (!w) return;
    _root = [[UIView alloc] initWithFrame:CGRectMake(16, 70, 210, 44)];
    _root.backgroundColor = [UIColor colorWithWhite:0.07 alpha:0.92];
    _root.layer.cornerRadius = 12; _root.layer.borderWidth = 1;
    _root.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.15].CGColor;

    UILabel *t = [[UILabel alloc] initWithFrame:CGRectMake(14, 8, 150, 28)];
    t.text = @"MCHeat"; t.textColor = UIColor.whiteColor;
    t.font = [UIFont boldSystemFontOfSize:17];
    [_root addSubview:t];

    UIButton *f = [UIButton buttonWithType:UIButtonTypeSystem];
    f.frame = CGRectMake(168, 6, 34, 30);
    [f setTitle:@"–" forState:UIControlStateNormal];
    [f addTarget:self action:@selector(fold) forControlEvents:UIControlEventTouchUpInside];
    [_root addSubview:f];
    [_root addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(drag:)]];

    _panel = [[UIView alloc] initWithFrame:CGRectMake(0, 44, 210, 0)];
    _panel.clipsToBounds = YES;
    [_root addSubview:_panel];

    _status = [[UILabel alloc] initWithFrame:CGRectMake(14, 4, 185, 18)];
    _status.font = [UIFont systemFontOfSize:11];
    _status.textColor = [UIColor colorWithWhite:1 alpha:0.55];
    _status.text = @"ready";
    [_panel addSubview:_status];

    NSArray *names = @[@"Fly", @"Killaura", @"Nuker"];
    CGFloat y = 26;
    for (int i = 0; i < 3; i++) {
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(14, y, 130, 30)];
        l.text = names[i]; l.textColor = UIColor.whiteColor;
        l.font = [UIFont systemFontOfSize:14];
        [_panel addSubview:l];
        UISwitch *s = [[UISwitch alloc] initWithFrame:CGRectMake(155, y, 51, 31)];
        s.tag = i; s.onTintColor = [UIColor colorWithRed:0.2 green:0.75 blue:0.45 alpha:1];
        [s addTarget:self action:@selector(flip:) forControlEvents:UIControlEventValueChanged];
        [_panel addSubview:s];
        y += 38;
    }
    UILabel *rl = [[UILabel alloc] initWithFrame:CGRectMake(14, y, 130, 26)];
    rl.text = @"Radius"; rl.textColor = [UIColor colorWithWhite:1 alpha:0.7];
    rl.font = [UIFont systemFontOfSize:12];
    [_panel addSubview:rl];
    UISlider *sl = [[UISlider alloc] initWithFrame:CGRectMake(90, y, 105, 26)];
    sl.minimumValue = 2; sl.maximumValue = 12; sl.value = 4.5;
    [sl addTarget:self action:@selector(radius:) forControlEvents:UIControlEventValueChanged];
    [_panel addSubview:sl];

    _panel.frame = CGRectMake(0, 44, 210, y + 32);
    [w addSubview:_root];
}

- (void)fold {
    CGFloat h = _panel.frame.size.height > 0 ? 0 : 196;
    [UIView animateWithDuration:0.2 animations:^{
        self->_panel.frame = CGRectMake(0, 44, 210, h);
        self->_root.frame = CGRectMake(self->_root.frame.origin.x, self->_root.frame.origin.y, 210, 44 + h);
    }];
}

- (void)drag:(UIPanGestureRecognizer *)g {
    CGPoint p = [g translationInView:_root.superview];
    if (g.state == UIGestureRecognizerStateBegan) _grab = _root.center;
    _root.center = CGPointMake(_grab.x + p.x, _grab.y + p.y);
}

- (void)radius:(UISlider *)s {
    [Core setRadius:s.value];
    _status.text = [NSString stringWithFormat:@"radius %.1f", s.value];
}

- (void)flip:(UISwitch *)s {
    if (s.tag == 0) { [Core setFly:s.isOn]; _status.text = s.isOn ? @"fly ON" : @"fly OFF"; }
    else if (s.tag == 1) { [Core setKillaura:s.isOn]; _status.text = s.isOn ? @"killaura ON" : @"killaura OFF"; }
    else { [Core setNuker:s.isOn]; _status.text = s.isOn ? @"nuker ON" : @"nuker OFF"; }
}
@end

// ===== entry =====
%ctor {
    if (![[NSBundle mainBundle].bundleIdentifier isEqualToString:@"com.mojang.minecraftpe"]) return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        if (![Core prepare]) return;
        if (![Core installHooks]) NSLog(@"[MCHeat] tick hook failed");
        [[Menu shared] show];
    });
}
