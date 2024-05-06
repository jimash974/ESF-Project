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

/* GLOBALS */

//'skipAPple' flag
BOOL skipApple = NO;

//filter string
NSString* filterBy = nil;

//'prettyPrint' flag
BOOL prettyPrint = NO;

//'prettyPrint' flag
NSString* attack = nil;

/* FUNCTIONS */

//process user-specifed args
BOOL processArgs(NSArray* arguments);

//print usage
void usage(void);

//monitor
BOOL monitor(void);

//prettify JSON
NSString* prettifyJSON(NSString* output);

#endif /* main_h */
