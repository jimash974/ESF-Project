//
//  main.h
//  SkripsiTesting
//
//  Created by Jeremy Christopher on 05/04/24.
//

#ifndef main_h
#define main_h

#import <Cocoa/Cocoa.h>
#import "FileMonitor.h"
//#import "Process"

/* GLOBALS */

//'skipAPple' flag
BOOL skipSystem = NO;

//'skipRedCan' flag
BOOL skipRedCan = NO;

//filter string
NSString* filterBy = nil;

//'prettyPrint' flag
BOOL printJSON = NO;

//'prettyPrint' flag
NSString* attack = nil;

//'parseEnv' flag to capture environment variable information
BOOL parseEnv = NO;

// output all of the log
BOOL all = NO;

//ATOMIC STELARE PROPERTIES
int AS_Pid = 0;
int AS_Ioc_Count = 0;

//Lock Bit
//int LB = 0;
int LB_Pid = 0;
int LB_Ioc_Count = 0;

// Gimmick
int GM_Pid = 0;
int GM_Ioc_Count = 0;

// VPN
int VPN_Pid = 0;
int VPN_Ioc_Count = 0;

/* FUNCTIONS */

//process user-specifed args
BOOL processArgs(NSArray* arguments);

//print usage
void usage(void);

// File Monitor
BOOL fileMonitor(void);

// Process Monitor
BOOL processMonitor(void);

//prettify JSON
NSString* prettifyJSON(NSString* output);

#endif /* main_h */
