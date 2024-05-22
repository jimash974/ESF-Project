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
BOOL skipSystem = NO;

//'skipRedCan' flag
BOOL skipRedCan = NO;

//filter string
NSString* filterBy = nil;

//'prettyPrint' flag
BOOL printJSON = NO;

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
