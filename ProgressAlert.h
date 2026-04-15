#pragma once
#import <Foundation/Foundation.h>

// Call at dylib-constructor time (before UIKit is ready) — sets up buffer only
void progress_show(void);

// Call on the main thread when UIApplicationDidFinishLaunchingNotification fires
// — presents the alert and flushes all buffered lines
void progress_uikit_ready(void);

void progress_log(NSString *line);
void progress_ok(NSString *line);
void progress_fail(NSString *line);
void progress_warn(NSString *line);
void progress_set(float pct);
void progress_done(BOOL success);
