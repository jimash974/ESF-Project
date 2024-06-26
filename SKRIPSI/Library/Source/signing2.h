#ifndef Signing_h
#define Signing_h

#import "ProcessMonitorr.h"
#import "FileMonitor.h"

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>


/* FUNCTIONS */

//get the signing info of a item
// pid specified: extract dynamic code signing info
// path specified: generate static code signing info
NSMutableDictionary* generateSigningInfo2(Process22* process, NSUInteger options, SecCSFlags flags);

//extract signing info/check via dynamic code ref (process pid)
CFDictionaryRef dynamicCodeCheck2(Process22* process, SecCSFlags flags, NSMutableDictionary* signingInfo);

//extact signing info/check via static code ref (process path)
CFDictionaryRef staticCodeCheck2(Process22* process, SecCSFlags flags, NSMutableDictionary* signingInfo);

//determine who signed item
NSNumber* extractSigner2(SecStaticCodeRef code, SecCSFlags flags, BOOL isDynamic);

//validate a requirement
OSStatus validateRequirement2(SecStaticCodeRef code, SecRequirementRef requirement, SecCSFlags flags, BOOL isDynamic);

//extract (names) of signing auths
NSMutableArray* extractSigningAuths2(NSDictionary* signingDetails);

#endif
