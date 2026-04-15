@import UIKit;
#import <objc/runtime.h>
#import <objc/message.h>
#import <xpc/xpc.h>

#include "kexploit/kexploit_opa334.h"
#include "kexploit/kutils.h"
#include "kexploit/offsets.h"
#include "kexploit/krw.h"
#include "sandbox_escape.h"
#include "ProgressAlert.h"

#pragma mark - Root Helper Hooks

static BOOL hook_isRootHelperAvailable(id self, SEL _cmd) {
    return NO;
}

static int hook_spawnRootHelper(id self, SEL _cmd) { return 0; }
static int hook_spawnRootHelperIfNeeds(id self, SEL _cmd) { return 0; }
static int hook_respawnRootHelper(id self, SEL _cmd) { return 0; }
static void hook_tryLoadFilzaHelper(id self, SEL _cmd) {}
static void hook_createHelperConnectionIfNeeds(id self, SEL _cmd) {}

static int hook_spawnRoot_args_pid(id self, SEL _cmd, id path, id args, int *pid) {
    if (pid) *pid = 0;
    return -1;
}

static id hook_sendObjectWithReplySync(id self, SEL _cmd, id msg) {
    return (id)xpc_null_create();
}

static id hook_sendObjectWithReplySync_fd(id self, SEL _cmd, id msg, int *fd) {
    if (fd) *fd = -1;
    return (id)xpc_null_create();
}

static id hook_sendObjectWithReplySync_fd_logintty(id self, SEL _cmd, id msg, int *fd, BOOL logintty) {
    if (fd) *fd = -1;
    return (id)xpc_null_create();
}

static void hook_sendObjectNoReply(id self, SEL _cmd, id msg) {}

static void hook_sendObjectWithReplyAsync(id self, SEL _cmd, id msg, id queue, id completion) {
    if (completion) { void (^block)(id) = completion; block(nil); }
}

#pragma mark - Zip/Unzip via minizip C API (linked in Filza binary)

// minizip C functions — statically linked in Filza, resolve via dlsym at runtime
#include <dlfcn.h>
typedef void* zipFile64;
typedef void* unzFile64;

// Function pointer types
static zipFile64 (*p_zipOpen64)(const char*, int);
static int (*p_zipOpenNewFileInZip64)(zipFile64, const char*, const void*, const void*, unsigned, const void*, unsigned, const char*, int, int, int);
static int (*p_zipWriteInFileInZip)(zipFile64, const void*, unsigned);
static int (*p_zipCloseFileInZip)(zipFile64);
static int (*p_zipClose)(zipFile64, const char*);
static unzFile64 (*p_unzOpen64)(const char*);
static int (*p_unzGoToFirstFile)(unzFile64);
static int (*p_unzGoToNextFile)(unzFile64);
static int (*p_unzGetCurrentFileInfo64)(unzFile64, void*, char*, unsigned long, void*, unsigned long, char*, unsigned long);
static int (*p_unzOpenCurrentFilePassword)(unzFile64, const char*);
static int (*p_unzReadCurrentFile)(unzFile64, void*, unsigned);
static int (*p_unzCloseCurrentFile)(unzFile64);
static int (*p_unzClose)(unzFile64);

static bool g_minizipLoaded = false;
static void loadMinizip(void) {
    if (g_minizipLoaded) return;
    // RTLD_DEFAULT searches all loaded images including Filza's statically linked minizip
    p_zipOpen64 = dlsym(RTLD_DEFAULT, "zipOpen64");
    p_zipOpenNewFileInZip64 = dlsym(RTLD_DEFAULT, "zipOpenNewFileInZip64");
    p_zipWriteInFileInZip = dlsym(RTLD_DEFAULT, "zipWriteInFileInZip");
    p_zipCloseFileInZip = dlsym(RTLD_DEFAULT, "zipCloseFileInZip");
    p_zipClose = dlsym(RTLD_DEFAULT, "zipClose");
    p_unzOpen64 = dlsym(RTLD_DEFAULT, "unzOpen64");
    p_unzGoToFirstFile = dlsym(RTLD_DEFAULT, "unzGoToFirstFile");
    p_unzGoToNextFile = dlsym(RTLD_DEFAULT, "unzGoToNextFile");
    p_unzGetCurrentFileInfo64 = dlsym(RTLD_DEFAULT, "unzGetCurrentFileInfo64");
    p_unzOpenCurrentFilePassword = dlsym(RTLD_DEFAULT, "unzOpenCurrentFilePassword");
    p_unzReadCurrentFile = dlsym(RTLD_DEFAULT, "unzReadCurrentFile");
    p_unzCloseCurrentFile = dlsym(RTLD_DEFAULT, "unzCloseCurrentFile");
    p_unzClose = dlsym(RTLD_DEFAULT, "unzClose");
    g_minizipLoaded = (p_zipOpen64 && p_unzOpen64);
    NSLog(@"[Tweak] minizip loaded: %d (zip=%p unz=%p)", g_minizipLoaded, p_zipOpen64, p_unzOpen64);
}

static IMP orig_ZipFiles = NULL, orig_unZipFile = NULL, orig_unZipFilePassword = NULL;

// Recursively add files to a zip archive using minizip C API
static void addFileToZip(zipFile64 zf, NSString *basePath, NSString *relativePath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *fullPath = [basePath stringByAppendingPathComponent:relativePath];
    BOOL isDir = NO;
    [fm fileExistsAtPath:fullPath isDirectory:&isDir];
    if (isDir) {
        // Add directory entry
        NSString *dirEntry = [relativePath stringByAppendingString:@"/"];
        p_zipOpenNewFileInZip64(zf, dirEntry.UTF8String, NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0);
        p_zipCloseFileInZip(zf);
        for (NSString *item in [fm contentsOfDirectoryAtPath:fullPath error:nil])
            addFileToZip(zf, basePath, [relativePath stringByAppendingPathComponent:item]);
    } else {
        NSData *data = [NSData dataWithContentsOfFile:fullPath];
        if (!data) return;
        // Z_DEFLATED=8, Z_DEFAULT_COMPRESSION=-1
        p_zipOpenNewFileInZip64(zf, relativePath.UTF8String, NULL, NULL, 0, NULL, 0, NULL, 8, -1, data.length > 0xFFFFFFFF);
        p_zipWriteInFileInZip(zf, data.bytes, (unsigned int)data.length);
        p_zipCloseFileInZip(zf);
    }
}

// Hook: -[Zipper ZipFiles:toFilePath:currentDirectory:]
static id hook_ZipFiles(id self, SEL _cmd, id files, id toFilePath, id currentDirectory) {
    @try {
        loadMinizip();
        if (!g_minizipLoaded) return orig_ZipFiles ? ((id(*)(id,SEL,id,id,id))orig_ZipFiles)(self, _cmd, files, toFilePath, currentDirectory) : nil;
        zipFile64 zf = p_zipOpen64(((NSString *)toFilePath).UTF8String, 0); // APPEND_STATUS_CREATE=0
        if (!zf) { NSLog(@"[Tweak] zipOpen64 failed"); return nil; }

        for (id fi in files) {
            NSString *fn = [fi performSelector:NSSelectorFromString(@"fileName")];
            if (fn) addFileToZip(zf, currentDirectory, fn);
        }
        p_zipClose(zf, NULL);

        // Return FileItem if zip was created (matching original behavior)
        if ([[NSFileManager defaultManager] fileExistsAtPath:toFilePath]) {
            Class FI = NSClassFromString(@"FileItem");
            if (FI) {
                id item = [[FI alloc] init];
                ((void(*)(id,SEL,id,id))objc_msgSend)(item, NSSelectorFromString(@"setFilePath:attribute:"), toFilePath, nil);
                return item;
            }
        }
        return nil;
    } @catch (NSException *e) { NSLog(@"[Tweak] Zip error: %@", e); return nil; }
}

// Hook: -[Zipper unZipFile:toPath:currentDirectory:outMessage:]
static id hook_unZipFile(id self, SEL _cmd, id zipPath, id toPath, id currentDir, id *outMsg) {
    @try {
        loadMinizip();
        if (!g_minizipLoaded) return orig_unZipFile ? ((id(*)(id,SEL,id,id,id,id*))orig_unZipFile)(self, _cmd, zipPath, toPath, currentDir, outMsg) : nil;
        // zipPath is a FileItem, get the actual path string
        NSString *zipPathStr = zipPath;
        if ([zipPath respondsToSelector:NSSelectorFromString(@"filePath")])
            zipPathStr = [zipPath performSelector:NSSelectorFromString(@"filePath")];

        unzFile64 uf = p_unzOpen64(((NSString *)zipPathStr).UTF8String);
        if (!uf) { if (outMsg) *outMsg = @"Failed to open zip"; return nil; }

        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *destPath = toPath;
        [fm createDirectoryAtPath:destPath withIntermediateDirectories:YES attributes:nil error:nil];

        char filename[512];
        uint8_t buf[32768];
        int ret = p_unzGoToFirstFile(uf);
        while (ret == 0) {
            p_unzGetCurrentFileInfo64(uf, NULL, filename, sizeof(filename), NULL, 0, NULL, 0);
            NSString *name = [NSString stringWithUTF8String:filename];
            NSString *fullPath = [destPath stringByAppendingPathComponent:name];

            if ([name hasSuffix:@"/"]) {
                [fm createDirectoryAtPath:fullPath withIntermediateDirectories:YES attributes:nil error:nil];
            } else {
                [fm createDirectoryAtPath:[fullPath stringByDeletingLastPathComponent]
                  withIntermediateDirectories:YES attributes:nil error:nil];

                if (p_unzOpenCurrentFilePassword(uf, NULL) == 0) {
                    NSMutableData *fileData = [NSMutableData data];
                    int bytesRead;
                    while ((bytesRead = p_unzReadCurrentFile(uf, buf, sizeof(buf))) > 0)
                        [fileData appendBytes:buf length:bytesRead];
                    p_unzCloseCurrentFile(uf);
                    [fileData writeToFile:fullPath atomically:YES];
                }
            }
            ret = p_unzGoToNextFile(uf);
        }
        p_unzClose(uf);

        if (outMsg) *outMsg = @"OK";

        // Return array of extracted FileItems (matching original behavior)
        NSArray *contents = [fm contentsOfDirectoryAtPath:destPath error:nil];
        if (contents.count > 0) {
            Class FI = NSClassFromString(@"FileItem");
            if (FI) {
                id item = [[FI alloc] init];
                ((void(*)(id,SEL,id,id))objc_msgSend)(item, NSSelectorFromString(@"setFilePath:attribute:"), destPath, nil);
                return @[item];
            }
        }
        return nil;
    } @catch (NSException *e) { NSLog(@"[Tweak] Unzip error: %@", e); if (outMsg) *outMsg = [e reason]; return nil; }
}

// Hook: -[Zipper unZipFile:toPath:currentDirectory:withPassword:outMessage:]
static id hook_unZipFilePassword(id self, SEL _cmd, id zipPath, id toPath, id currentDir, id password, id *outMsg) {
    return hook_unZipFile(self, @selector(unZipFile:toPath:currentDirectory:outMessage:), zipPath, toPath, currentDir, outMsg);
}

#pragma mark - Apps Manager Fix

// Full Apps Manager fix for sandbox-escaped devices.
// LSApplicationProxy properties (localizedName, iconsDictionary, dataContainerURL,
// staticDiskUsage, etc.) return nil without entitlements.
// Fix: Hook setAppProxy: to populate from Info.plist + filesystem directly.
// Hook calculateDiskUsage to walk bundle dirs. Hook tap to use bundle path fallback.

@interface LSApplicationProxy : NSObject
+ (id)applicationProxyForIdentifier:(NSString *)bundleId;
- (NSString *)applicationIdentifier;
- (NSURL *)bundleURL;
- (NSURL *)dataContainerURL;
- (NSString *)localizedName;
- (NSString *)bundleVersion;
- (NSString *)shortVersionString;
- (NSString *)applicationType;
- (NSDictionary *)iconsDictionary;
- (NSNumber *)staticDiskUsage;
- (NSNumber *)dynamicDiskUsage;
@end

@interface LSApplicationWorkspace : NSObject
+ (id)defaultWorkspace;
- (NSArray *)allApplications;
@end

// --- Helper: find app bundle path from bundleId ---
static NSString *findBundlePath(NSString *bundleId) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *appsDir = @"/var/containers/Bundle/Application";
    for (NSString *uuid in [fm contentsOfDirectoryAtPath:appsDir error:nil]) {
        NSString *uuidPath = [appsDir stringByAppendingPathComponent:uuid];
        for (NSString *item in [fm contentsOfDirectoryAtPath:uuidPath error:nil]) {
            if (![item hasSuffix:@".app"]) continue;
            NSString *appPath = [uuidPath stringByAppendingPathComponent:item];
            NSString *plist = [appPath stringByAppendingPathComponent:@"Info.plist"];
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
            if ([info[@"CFBundleIdentifier"] isEqualToString:bundleId]) return appPath;
        }
    }
    // System apps
    for (NSString *item in [fm contentsOfDirectoryAtPath:@"/Applications" error:nil]) {
        if (![item hasSuffix:@".app"]) continue;
        NSString *appPath = [@"/Applications" stringByAppendingPathComponent:item];
        NSString *plist = [appPath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        if ([info[@"CFBundleIdentifier"] isEqualToString:bundleId]) return appPath;
    }
    return nil;
}

// --- Helper: find data container path ---
static NSString *findDataContainer(NSString *bundleId) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dataDir = @"/var/mobile/Containers/Data/Application";
    for (NSString *uuid in [fm contentsOfDirectoryAtPath:dataDir error:nil]) {
        NSString *uuidPath = [dataDir stringByAppendingPathComponent:uuid];
        NSString *metaPlist = [uuidPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPlist];
        if ([meta[@"MCMMetadataIdentifier"] isEqualToString:bundleId]) return uuidPath;
    }
    return nil;
}

// --- Helper: find best icon in bundle ---
static NSString *findIconPath(NSString *bundlePath, NSDictionary *infoPlist) {
    NSFileManager *fm = [NSFileManager defaultManager];
    // Try CFBundleIcons -> CFBundlePrimaryIcon -> CFBundleIconFiles
    NSDictionary *icons = infoPlist[@"CFBundleIcons"];
    NSDictionary *primary = icons[@"CFBundlePrimaryIcon"];
    NSArray *iconFiles = primary[@"CFBundleIconFiles"];
    if (!iconFiles) iconFiles = infoPlist[@"CFBundleIconFiles"];

    NSString *bestIcon = nil;
    unsigned long long bestSize = 0;
    if (iconFiles.count > 0) {
        for (NSString *iconName in iconFiles) {
            // Try exact name and @2x/@3x variants
            NSArray *variants = @[
                iconName,
                [iconName stringByAppendingString:@"@2x.png"],
                [iconName stringByAppendingString:@"@3x.png"],
                [iconName stringByAppendingString:@"@2x~iphone.png"],
                [iconName stringByAppendingString:@"@3x~iphone.png"],
                [NSString stringWithFormat:@"%@.png", iconName],
            ];
            for (NSString *v in variants) {
                NSString *full = [bundlePath stringByAppendingPathComponent:v];
                NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
                unsigned long long sz = [attrs fileSize];
                if (sz > bestSize) { bestSize = sz; bestIcon = full; }
            }
        }
    }

    // Fallback: scan for Icon*.png / AppIcon*.png
    if (!bestIcon) {
        for (NSString *file in [fm contentsOfDirectoryAtPath:bundlePath error:nil]) {
            if (([file hasPrefix:@"Icon"] || [file hasPrefix:@"icon"] || [file hasPrefix:@"AppIcon"])
                && [file hasSuffix:@".png"]) {
                NSString *full = [bundlePath stringByAppendingPathComponent:file];
                NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
                unsigned long long sz = [attrs fileSize];
                if (sz > bestSize) { bestSize = sz; bestIcon = full; }
            }
        }
    }
    return bestIcon;
}

// --- Hook: allApplications fallback ---
static IMP orig_allApplications = NULL;
static id hook_allApplications(id self, SEL _cmd) {
    NSArray *origResult = ((id(*)(id,SEL))orig_allApplications)(self, _cmd);
    if (origResult && origResult.count > 0) return origResult;

    NSMutableArray *apps = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    void (^scanDir)(NSString *) = ^(NSString *dir) {
        for (NSString *uuid in [fm contentsOfDirectoryAtPath:dir error:nil]) {
            NSString *uuidPath = [dir stringByAppendingPathComponent:uuid];
            for (NSString *item in [fm contentsOfDirectoryAtPath:uuidPath error:nil]) {
                if (![item hasSuffix:@".app"]) continue;
                NSString *plist = [[uuidPath stringByAppendingPathComponent:item] stringByAppendingPathComponent:@"Info.plist"];
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
                NSString *bid = info[@"CFBundleIdentifier"];
                if (bid) {
                    id proxy = [NSClassFromString(@"LSApplicationProxy") applicationProxyForIdentifier:bid];
                    if (proxy) [apps addObject:proxy];
                }
            }
        }
    };
    scanDir(@"/var/containers/Bundle/Application");
    // System apps (flat structure)
    for (NSString *item in [fm contentsOfDirectoryAtPath:@"/Applications" error:nil]) {
        if (![item hasSuffix:@".app"]) continue;
        NSString *plist = [[@"/Applications" stringByAppendingPathComponent:item] stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        NSString *bid = info[@"CFBundleIdentifier"];
        if (bid) {
            id proxy = [NSClassFromString(@"LSApplicationProxy") applicationProxyForIdentifier:bid];
            if (proxy) [apps addObject:proxy];
        }
    }
    NSLog(@"[Tweak] Apps Manager: found %lu apps via filesystem", (unsigned long)apps.count);
    return apps;
}

// --- Hook: setAppProxy: — populate name, icon, paths from filesystem ---
static IMP orig_setAppProxy = NULL;
static void hook_setAppProxy(id self, SEL _cmd, id proxy) {
    // Call original first
    ((void(*)(id,SEL,id))orig_setAppProxy)(self, _cmd, proxy);

    NSString *bundleId = [self performSelector:NSSelectorFromString(@"bundleId")];
    if (!bundleId) return;

    NSString *bundlePath = nil;
    NSString *currentFilePath = [self performSelector:NSSelectorFromString(@"filePath")];

    // Fix filePath if missing or inaccessible
    if (!currentFilePath || currentFilePath.length == 0) {
        NSURL *bundleURL = [proxy bundleURL];
        if (bundleURL) bundlePath = [bundleURL path];
        if (!bundlePath) bundlePath = findBundlePath(bundleId);
        if (bundlePath) {
            ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setFilePath:"), bundlePath);
        }
    } else {
        bundlePath = currentFilePath;
    }

    // Fix display name — always prefer Info.plist name over proxy
    if (bundlePath) {
        NSString *plist = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        NSString *name = info[@"CFBundleDisplayName"];
        if (!name) name = info[@"CFBundleName"];
        if (!name) name = [proxy localizedName];
        if (!name) name = bundleId;
        ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setAFileName:"), name);
    }

    // Fix icon path
    NSString *iconPath = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"iconPath"));
    if (!iconPath && bundlePath) {
        NSString *plist = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        NSString *found = findIconPath(bundlePath, info);
        if (found) {
            ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setIconPath:"), found);
        }
    }

    // Fix document path
    NSString *docPath = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"documentPath"));
    if (!docPath) {
        NSURL *dataURL = [proxy dataContainerURL];
        if (dataURL) docPath = [dataURL path];
        if (!docPath) docPath = findDataContainer(bundleId);
        if (docPath) {
            ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setDocumentPath:"), docPath);
        }
    }

    // Fix version
    NSString *ver = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"version"));
    if (!ver || ver.length == 0) {
        ver = [proxy bundleVersion];
        if (!ver && bundlePath) {
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                [bundlePath stringByAppendingPathComponent:@"Info.plist"]];
            ver = info[@"CFBundleShortVersionString"];
            if (!ver) ver = info[@"CFBundleVersion"];
        }
        if (ver) ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setVersion:"), ver);
    }
}


// --- Hook: browserView:didSelectItemAtIndexPath: — fallback to bundle path ---
static IMP orig_didSelectItem = NULL;
static void hook_didSelectItem(id self, SEL _cmd, id browserView, id indexPath) {
    // Get the selected item
    id fileList = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"fileList"));
    NSUInteger row = ((NSUInteger(*)(id,SEL))objc_msgSend)(indexPath, @selector(row));
    id item = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(fileList, NSSelectorFromString(@"objectAtIndex:"), row);

    NSString *docPath = ((id(*)(id,SEL))objc_msgSend)(item, NSSelectorFromString(@"documentPath"));
    NSString *bundlePath = [item performSelector:NSSelectorFromString(@"filePath")];

    // If documentPath is nil but bundlePath exists, set documentPath to bundlePath
    // so the original handler can navigate there instead of showing error
    if (!docPath && bundlePath) {
        ((void(*)(id,SEL,id))objc_msgSend)(item, NSSelectorFromString(@"setDocumentPath:"), bundlePath);
    }

    // Call original
    ((void(*)(id,SEL,id,id))orig_didSelectItem)(self, _cmd, browserView, indexPath);
}

#pragma mark - License / Integrity Bypass

// Suppress "Main binary was modified" and "Not activated" alerts.
// +[TGAlertController showAlertWithTitle:text:cancelButton:otherButtons:completion:]
// checks the text parameter; if it's the integrity/activation alert, swallow it.
static IMP orig_showAlert = NULL;
static id hook_showAlertWithTitle(id self, SEL _cmd, id title, id text, id cancelButton, id otherButtons, id completion) {
    NSString *textStr = text;
    if ([textStr isKindOfClass:[NSString class]]) {
        if ([textStr containsString:@"binary was modified"] ||
            [textStr containsString:@"reinstall Filza"]) {
            NSLog(@"[Tweak] Suppressed integrity alert");
            return nil;
        }
    }
    // Pass through all other alerts
    return ((id(*)(id,SEL,id,id,id,id,id))orig_showAlert)(self, _cmd, title, text, cancelButton, otherButtons, completion);
}

// Suppress activation nag: -[NewActivationViewController viewDidLoad]
// Just dismiss the VC immediately so the user never sees it.
static IMP orig_activationViewDidLoad = NULL;
static void hook_activationViewDidLoad(id self, SEL _cmd) {
    // Call original to set up the VC, then immediately dismiss
    ((void(*)(id,SEL))orig_activationViewDidLoad)(self, _cmd);
    dispatch_async(dispatch_get_main_queue(), ^{
        ((void(*)(id,SEL,BOOL,id))objc_msgSend)(self,
            NSSelectorFromString(@"dismissViewControllerAnimated:completion:"), NO, nil);
    });
    NSLog(@"[Tweak] Suppressed activation nag");
}

#pragma mark - Hook Installation (instrumented)

// Helper: install a single hook and report result
#define HOOK_INSTANCE(cls, selStr, imp, types) \
    do { \
        Method _m = class_getInstanceMethod(cls, NSSelectorFromString(selStr)); \
        if (_m) { method_setImplementation(_m, (IMP)(imp)); \
            progress_ok([NSString stringWithFormat:@"-[%s %s]", class_getName(cls), selStr]); } \
        else { progress_warn([NSString stringWithFormat:@"not found: -[%s %s]", class_getName(cls), selStr]); } \
    } while(0)

#define HOOK_INSTANCE_SAVE(cls, selStr, imp, types, origPtr) \
    do { \
        Method _m = class_getInstanceMethod(cls, NSSelectorFromString(selStr)); \
        if (_m) { *(origPtr) = method_getImplementation(_m); method_setImplementation(_m, (IMP)(imp)); \
            progress_ok([NSString stringWithFormat:@"-[%s %s]", class_getName(cls), selStr]); } \
        else { progress_warn([NSString stringWithFormat:@"not found: -[%s %s]", class_getName(cls), selStr]); } \
    } while(0)

#define HOOK_CLASS_SAVE(cls, selStr, imp, types, origPtr) \
    do { \
        Class _meta = object_getClass(cls); \
        Method _m = class_getClassMethod(cls, NSSelectorFromString(selStr)); \
        if (_m) { *(origPtr) = method_getImplementation(_m); \
            class_replaceMethod(_meta, NSSelectorFromString(selStr), (IMP)(imp), types); \
            progress_ok([NSString stringWithFormat:@"+[%s %s]", class_getName(cls), selStr]); } \
        else { progress_warn([NSString stringWithFormat:@"not found: +[%s %s]", class_getName(cls), selStr]); } \
    } while(0)

#define REPLACE_CLASS(cls, selStr, imp, types) \
    do { \
        class_replaceMethod(cls, NSSelectorFromString(selStr), (IMP)(imp), types); \
        progress_ok([NSString stringWithFormat:@"-[%s %s]", class_getName(cls), selStr]); \
    } while(0)

#define REPLACE_META(meta, cls, selStr, imp, types) \
    do { \
        class_replaceMethod(meta, NSSelectorFromString(selStr), (IMP)(imp), types); \
        progress_ok([NSString stringWithFormat:@"+[%s %s]", class_getName(cls), selStr]); \
    } while(0)

static void installHooks(void) {
    // ── 1. Root-helper bypass ─────────────────────────────────────────────────
    progress_log(@"Stage 1/4: root-helper bypass hooks");
    Class rfm = NSClassFromString(@"TGRootFileManager");
    if (rfm) {
        Class meta = object_getClass(rfm);
        REPLACE_META(meta, rfm, @"isRootHelperAvailable",            hook_isRootHelperAvailable,            "B@:");
        REPLACE_CLASS(rfm,      @"spawnRootHelper",                   hook_spawnRootHelper,                  "i@:");
        REPLACE_CLASS(rfm,      @"spawnRootHelperIfNeeds",            hook_spawnRootHelperIfNeeds,           "i@:");
        REPLACE_CLASS(rfm,      @"respawnRootHelper",                 hook_respawnRootHelper,                "i@:");
        REPLACE_CLASS(rfm,      @"tryLoadFilzaHelper",                hook_tryLoadFilzaHelper,               "v@:");
        REPLACE_CLASS(rfm,      @"createHelperConnectionIfNeeds",     hook_createHelperConnectionIfNeeds,    "v@:");
        REPLACE_CLASS(rfm,      @"spawnRoot:args:pid:",               hook_spawnRoot_args_pid,               "i@:@@^i");
        REPLACE_CLASS(rfm,      @"sendObjectWithReplySync:",          hook_sendObjectWithReplySync,          "@@:@");
        REPLACE_CLASS(rfm,      @"sendObjectWithReplySync:fileDescriptor:",
                                                                       hook_sendObjectWithReplySync_fd,       "@@:@^i");
        REPLACE_CLASS(rfm,      @"sendObjectWithReplySync:fileDescriptor:logintty:",
                                                                       hook_sendObjectWithReplySync_fd_logintty, "@@:@^iB");
        REPLACE_CLASS(rfm,      @"sendObjectNoReply:",                hook_sendObjectNoReply,                "v@:@");
        REPLACE_CLASS(rfm,      @"sendObjectWithReplyAsync:queue:completion:",
                                                                       hook_sendObjectWithReplyAsync,         "v@:@@?");
        progress_ok(@"TGRootFileManager — 12 methods patched");
    } else {
        progress_warn(@"TGRootFileManager not found (class not loaded yet?)");
    }
    progress_set(10.f);

    // ── 2. Zip / unzip hooks ──────────────────────────────────────────────────
    progress_log(@"Stage 2/4: zip/unzip hooks");
    Class zipper = NSClassFromString(@"Zipper");
    if (zipper) {
        HOOK_INSTANCE_SAVE(zipper, @"ZipFiles:toFilePath:currentDirectory:",
                           hook_ZipFiles, "@@:@@@", &orig_ZipFiles);
        HOOK_INSTANCE_SAVE(zipper, @"unZipFile:toPath:currentDirectory:outMessage:",
                           hook_unZipFile, "@@:@@@^@", &orig_unZipFile);
        HOOK_INSTANCE_SAVE(zipper, @"unZipFile:toPath:currentDirectory:withPassword:outMessage:",
                           hook_unZipFilePassword, "@@:@@@@^@", &orig_unZipFilePassword);
        progress_ok(@"Zipper — 3 methods patched");
    } else {
        progress_warn(@"Zipper not found (minizip hooks skipped)");
    }
    progress_set(20.f);

    // ── 3. License / integrity bypass ─────────────────────────────────────────
    progress_log(@"Stage 3/4: license + activation bypass");
    Class alertCtrl = NSClassFromString(@"TGAlertController");
    if (alertCtrl) {
        HOOK_CLASS_SAVE(alertCtrl,
                        @"showAlertWithTitle:text:cancelButton:otherButtons:completion:",
                        hook_showAlertWithTitle, "@@:@@@@@", &orig_showAlert);
    } else {
        progress_warn(@"TGAlertController not found");
    }
    Class activationVC = NSClassFromString(@"NewActivationViewController");
    if (activationVC) {
        HOOK_INSTANCE_SAVE(activationVC, @"viewDidLoad",
                           hook_activationViewDidLoad, "v@:", &orig_activationViewDidLoad);
    } else {
        progress_warn(@"NewActivationViewController not found");
    }
    progress_set(30.f);

    // ── 4. Apps Manager fixes ─────────────────────────────────────────────────
    progress_log(@"Stage 4/4: Apps Manager hooks");
    Class lsWorkspace = NSClassFromString(@"LSApplicationWorkspace");
    if (lsWorkspace) {
        HOOK_INSTANCE_SAVE(lsWorkspace, @"allApplications",
                           hook_allApplications, "@@:", &orig_allApplications);
    } else {
        progress_warn(@"LSApplicationWorkspace not found");
    }
    Class appItem = NSClassFromString(@"ApplicationItem");
    if (appItem) {
        HOOK_INSTANCE_SAVE(appItem, @"setAppProxy:",
                           hook_setAppProxy, "v@:@", &orig_setAppProxy);
    } else {
        progress_warn(@"ApplicationItem not found");
    }
    Class appsVC = NSClassFromString(@"TGApplicationsViewController");
    if (appsVC) {
        HOOK_INSTANCE_SAVE(appsVC, @"browserView:didSelectItemAtIndexPath:",
                           hook_didSelectItem, "v@:@@", &orig_didSelectItem);
    } else {
        progress_warn(@"TGApplicationsViewController not found");
    }
    progress_set(40.f);
    progress_ok(@"All hooks installed");
}

#pragma mark - Exploit (instrumented)

static void runExploit(void) {
    // ── Kernel exploit ────────────────────────────────────────────────────────
    progress_log(@"Running kexploit_opa334…");
    progress_set(45.f);

    int kret = kexploit_opa334();

    if (kret != 0) {
        progress_fail([NSString stringWithFormat:@"kexploit_opa334 FAILED (ret=%d)", kret]);
        progress_set(100.f);
        progress_done(NO);
        return;
    }
    progress_ok([NSString stringWithFormat:@"kexploit_opa334 succeeded (ret=%d)", kret]);
    progress_set(65.f);

    // ── Dump all offsets used by proc_self() before touching kernel memory ────
    sleep(2);
    progress_log([NSString stringWithFormat:
        @"[DBG] offsets dump: rwSocketPcb=0x%llx", rwSocketPcb]);
    progress_log([NSString stringWithFormat:
        @"[DBG]   off_inpcb_inp_socket=0x%x", off_inpcb_inp_socket]);
    progress_log([NSString stringWithFormat:
        @"[DBG]   off_socket_so_background_thread=0x%x", off_socket_so_background_thread]);
    progress_log([NSString stringWithFormat:
        @"[DBG]   off_thread_t_tro=0x%x", off_thread_t_tro]);
    progress_log([NSString stringWithFormat:
        @"[DBG]   off_thread_ro_tro_proc=0x%x", off_thread_ro_tro_proc]);
    progress_log([NSString stringWithFormat:
        @"[DBG]   VM_MIN=0x%llx  VM_MAX=0x%llx", VM_MIN_KERNEL_ADDRESS, VM_MAX_KERNEL_ADDRESS]);
    sleep(2);

    // ── Inline proc_self() step by step ──────────────────────────────────────
    // Step A: read socket address from inpcb
    uint64_t dbg_target_A = rwSocketPcb + off_inpcb_inp_socket;
    progress_log([NSString stringWithFormat:
        @"[DBG] procSelf A — about to kread64(rwSocketPcb+off_inpcb_inp_socket) @ 0x%llx", dbg_target_A]);
    sleep(2);
    uint64_t rwSocketAddr = kread64(dbg_target_A);
    progress_ok([NSString stringWithFormat:@"[DBG] procSelf A returned rwSocketAddr=0x%llx  valid=%s",
        rwSocketAddr, is_kaddr_valid(rwSocketAddr) ? "YES" : "NO ← PROBLEM"]);
    sleep(2);

    // Step B: read background_thread from socket
    uint64_t dbg_target_B = rwSocketAddr + off_socket_so_background_thread;
    progress_log([NSString stringWithFormat:
        @"[DBG] procSelf B — about to kread64(rwSocketAddr+off_so_bg_thread) @ 0x%llx", dbg_target_B]);
    sleep(2);
    uint64_t current_thread = kread64(dbg_target_B);
    progress_ok([NSString stringWithFormat:@"[DBG] procSelf B returned current_thread=0x%llx  valid=%s",
        current_thread, is_kaddr_valid(current_thread) ? "YES" : "NO ← PROBLEM"]);
    sleep(2);

    // Step C: read t_tro from thread
    uint64_t dbg_target_C = current_thread + off_thread_t_tro;
    progress_log([NSString stringWithFormat:
        @"[DBG] procSelf C — about to kread64(current_thread+off_thread_t_tro) @ 0x%llx", dbg_target_C]);
    sleep(2);
    uint64_t current_thread_ro = kread64(dbg_target_C);
    progress_ok([NSString stringWithFormat:@"[DBG] procSelf C returned current_thread_ro=0x%llx  valid=%s",
        current_thread_ro, is_kaddr_valid(current_thread_ro) ? "YES" : "NO ← PROBLEM"]);
    sleep(2);

    // Step D: read tro_proc from thread_ro
    uint64_t dbg_target_D = current_thread_ro + off_thread_ro_tro_proc;
    progress_log([NSString stringWithFormat:
        @"[DBG] procSelf D — about to kread64(current_thread_ro+off_tro_proc) @ 0x%llx", dbg_target_D]);
    sleep(2);
    uint64_t self_proc_addr = kread64(dbg_target_D);
    progress_ok([NSString stringWithFormat:@"[DBG] procSelf D returned self_proc=0x%llx  valid=%s",
        self_proc_addr, is_kaddr_valid(self_proc_addr) ? "YES" : "NO ← PROBLEM"]);
    sleep(2);

    if (self_proc_addr) {
        progress_ok([NSString stringWithFormat:@"proc_self() = 0x%llx", self_proc_addr]);
    } else {
        progress_fail(@"proc_self() returned 0 — KRW may be broken");
    }
    progress_set(68.f);

    // ── Sandbox escape ────────────────────────────────────────────────────────
    progress_log(@"Running sandbox_escape()…");
    int sret = sandbox_escape(self_proc_addr);

    if (sret == 0) {
        progress_ok([NSString stringWithFormat:@"sandbox_escape succeeded (ret=%d)", sret]);
    } else {
        progress_fail([NSString stringWithFormat:@"sandbox_escape FAILED (ret=%d)", sret]);
    }

    // ── Final end-to-end verification ─────────────────────────────────────────
    progress_log(@"Final verification: writing to /var/mobile/…");
    progress_set(95.f);
    int fd_final = open("/var/mobile/.jds_final_check", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_final >= 0) {
        close(fd_final);
        unlink("/var/mobile/.jds_final_check");
        progress_ok(@"Write to /var/mobile/ succeeded — R+W confirmed");
        progress_set(100.f);
        progress_done(YES);
    } else {
        progress_fail([NSString stringWithFormat:@"Write to /var/mobile/ FAILED (errno=%d: %s)",
                       errno, strerror(errno)]);
        progress_set(100.f);
        progress_done(NO);
    }
}

#pragma mark - Entry Point

__attribute__((constructor)) void TweakInit(void) {
    // Set up the line buffer (UIKit not ready yet — nothing can be presented)
    progress_show();

    // Install all hooks — lines are buffered until the alert is presented
    installHooks();

    // UIApplicationDidFinishLaunchingNotification fires on the main thread,
    // which is the earliest safe point to present a UIAlertController.
    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationDidFinishLaunchingNotification
                    object:nil
                     queue:[NSOperationQueue mainQueue]   // ensure main thread
                usingBlock:^(NSNotification *note) {

        // Present the alert and flush all buffered hook-install lines into it
        progress_uikit_ready();

        // Give the alert's presentation animation ~0.1 s to start, then run
        // the exploit on a background thread (buffering handles any lines that
        // arrive before the completion block fires and marks _presented = YES)
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
            dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
            ^{
                // ── Pre-flight sandbox check ───────────────────────────────
                progress_log(@"Pre-flight: checking if sandbox already escaped…");
                int fd = open("/var/mobile/.sbx_check", O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd >= 0) {
                    close(fd); unlink("/var/mobile/.sbx_check");
                    progress_ok(@"Sandbox already escaped — skipping exploit");
                    progress_set(100.f);
                    progress_done(YES);
                    return;
                }
                progress_log([NSString stringWithFormat:
                    @"Not yet escaped (errno=%d) — running exploit", errno]);
                progress_set(42.f);

                runExploit();
            });
    }];
}
