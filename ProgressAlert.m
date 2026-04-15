/*
 * ProgressAlert.m — Live UIAlertController progress log
 *
 * TweakInit() fires at dylib-load time, before UIKit has any windows.
 * Strategy:
 *   1. progress_show()       — called at constructor time; just sets up the buffer
 *   2. progress_log/ok/etc.  — buffer lines into _pendingLines until UIKit is ready
 *   3. progress_uikit_ready()— called on the main thread when UIApplicationDidFinishLaunchingNotification
 *                              fires; presents the alert and flushes the buffer
 *   4. All subsequent calls  — update _alert.message live on the main thread
 */

#import "ProgressAlert.h"
@import UIKit;

// ── state ─────────────────────────────────────────────────────────────────────
static UIAlertController  *_alert        = nil;
static NSMutableArray     *_pendingLines = nil;   // buffered before UIKit ready
static NSMutableString    *_log          = nil;   // accumulated log for live updates
static float               _pct          = 0.f;
static BOOL                _presented    = NO;
static dispatch_queue_t    _q            = nil;   // serial queue protecting all state

// ── file logging ──────────────────────────────────────────────────────────────
static FILE *_logFile = NULL;

static void _file_log_init(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSArray *dirs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *docsDir = dirs.firstObject;
        if (!docsDir) return;

        // Timestamped filename so each run produces a fresh file
        NSDateFormatter *fmt = [NSDateFormatter new];
        fmt.dateFormat = @"yyyyMMdd_HHmmss";
        NSString *stamp = [fmt stringFromDate:[NSDate date]];
        NSString *path = [docsDir stringByAppendingPathComponent:
            [NSString stringWithFormat:@"FilzaJailedDS_%@.log", stamp]];

        _logFile = fopen(path.UTF8String, "w");
        if (_logFile) {
            fprintf(_logFile, "=== FilzaJailedDS log  %s ===\n",
                    stamp.UTF8String);
            fflush(_logFile);
        }
    });
}

static void _file_log_write(NSString *line) {
    if (!_logFile) return;
    // Timestamp each line: HH:mm:ss.SSS
    NSDateFormatter *fmt = [NSDateFormatter new];
    fmt.dateFormat = @"HH:mm:ss.SSS";
    NSString *ts = [fmt stringFromDate:[NSDate date]];
    fprintf(_logFile, "[%s] %s\n", ts.UTF8String, line.UTF8String);
    fflush(_logFile);
}

#define MAX_LOG_LINES 30

// ── progress bar ──────────────────────────────────────────────────────────────
static NSString *makeBar(float pct) {
    int filled = (int)roundf(pct / 5.f);
    filled = filled < 0 ? 0 : (filled > 20 ? 20 : filled);
    NSMutableString *bar = [NSMutableString stringWithCapacity:28];
    [bar appendString:@"["];
    for (int i = 0; i < 20; i++)
        [bar appendString:(i < filled) ? @"█" : @"░"];
    [bar appendFormat:@"] %3.0f%%", pct];
    return bar;
}

// ── push updated message to the alert (must hold _q, marshals to main thread) ─
static void _pushMessage(void) {
    if (!_presented || !_alert) return;
    NSString *bar  = makeBar(_pct);
    NSString *body = [NSString stringWithFormat:@"%@\n\n%@", bar, _log];
    dispatch_async(dispatch_get_main_queue(), ^{
        _alert.message = body;
    });
}

// ── append one line to _log (trims to MAX_LOG_LINES) ─────────────────────────
static void _append(NSString *line) {
    if (!_log) _log = [NSMutableString string];
    [_log appendFormat:@"%@\n", line];

    NSArray<NSString *> *lines = [_log componentsSeparatedByString:@"\n"];
    if ((NSInteger)lines.count > MAX_LOG_LINES + 1) {
        NSArray *kept = [lines subarrayWithRange:
            NSMakeRange(lines.count - MAX_LOG_LINES - 1, MAX_LOG_LINES)];
        [_log setString:[kept componentsJoinedByString:@"\n"]];
        [_log appendString:@"\n"];
    }
    _pushMessage();
}

// ── find the topmost presented view controller ────────────────────────────────
static UIViewController *_topVC(void) {
    UIWindow *win = nil;
    for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if ([scene isKindOfClass:[UIWindowScene class]] &&
            scene.activationState == UISceneActivationStateForegroundActive) {
            for (UIWindow *w in [(UIWindowScene *)scene windows]) {
                if (w.isKeyWindow) { win = w; break; }
            }
        }
        if (win) break;
    }
    if (!win) {
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (w.isKeyWindow) { win = w; break; }
        }
    }
    if (!win) win = [UIApplication sharedApplication].windows.firstObject;

    UIViewController *vc = win.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

// ── public API ────────────────────────────────────────────────────────────────

// Call at constructor time (before UIKit is ready) — sets up buffer only.
void progress_show(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        _q            = dispatch_queue_create("jds.progress", DISPATCH_QUEUE_SERIAL);
        _pendingLines = [NSMutableArray array];
        _log          = [NSMutableString string];
        _file_log_init();
    });
}

// Call on the main thread when UIApplicationDidFinishLaunchingNotification fires.
// Presents the alert and flushes all buffered lines into it.
void progress_uikit_ready(void) {
    // Build the alert
    _alert = [UIAlertController
        alertControllerWithTitle:@"FilzaJailedDS  —  Running"
                         message:[NSString stringWithFormat:@"%@\n\n(starting…)", makeBar(_pct)]
                  preferredStyle:UIAlertControllerStyleAlert];

    UIAlertAction *btn = [UIAlertAction actionWithTitle:@"Running…"
                                                  style:UIAlertActionStyleDefault
                                                handler:nil];
    [btn setValue:@NO forKey:@"enabled"];
    [_alert addAction:btn];

    UIViewController *vc = _topVC();
    if (!vc) {
        // If still no VC somehow, try again after a short delay
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            progress_uikit_ready();
        });
        return;
    }

    [vc presentViewController:_alert animated:YES completion:^{
        // Mark presented, then flush the buffered lines
        dispatch_async(_q, ^{
            _presented = YES;
            // Flush pending lines accumulated before UIKit was ready
            if (_pendingLines.count > 0) {
                for (NSString *line in _pendingLines)
                    _append(line);
                [_pendingLines removeAllObjects];
            }
            _pushMessage();
        });
    }];
}

// ── line-adding helpers ───────────────────────────────────────────────────────

static void _buffer_or_append(NSString *formatted) {
    NSLog(@"[JDS] %@", formatted);
    _file_log_init();       // no-op after first call
    _file_log_write(formatted);
    dispatch_async(_q, ^{
        if (_presented) {
            _append(formatted);
        } else {
            [_pendingLines addObject:formatted];
        }
    });
}

void progress_log(NSString *line) {
    _buffer_or_append([NSString stringWithFormat:@"  %@", line]);
}

void progress_ok(NSString *line) {
    _buffer_or_append([NSString stringWithFormat:@"✅ %@", line]);
}

void progress_fail(NSString *line) {
    _buffer_or_append([NSString stringWithFormat:@"❌ %@", line]);
}

void progress_warn(NSString *line) {
    _buffer_or_append([NSString stringWithFormat:@"⚠️  %@", line]);
}

void progress_set(float pct) {
    dispatch_async(_q, ^{
        _pct = pct;
        _pushMessage();
    });
}

void progress_done(BOOL success) {
    NSString *title = success
        ? @"FilzaJailedDS  —  ✅ Done"
        : @"FilzaJailedDS  —  ❌ Failed";
    NSString *btn = success
        ? @"OK (sandbox escaped)"
        : @"OK (failed — see log)";
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!_alert) return;
        _alert.title = title;
        [_alert.actions.firstObject setValue:btn  forKey:@"title"];
        [_alert.actions.firstObject setValue:@YES forKey:@"enabled"];
    });
}
