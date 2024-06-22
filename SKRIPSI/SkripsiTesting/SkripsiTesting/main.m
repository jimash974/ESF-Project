//
//  main.m
//  SkripsiTesting
//
//  Created by Jeremy Christopher on 02/04/24.
//

#import "main.h"
#import "FileMonitor.h"
//#import "ProcessMonitor.h"
//#import <ProcessMonitor.h>
#import <ProcessMonitorr.h>

int main(int argc, const char * argv[]) {
    
    //return var
    int status = -1;
    
    @autoreleasepool {
        NSArray* arguments = nil;
        
        arguments = [[NSProcessInfo processInfo] arguments];
        processArgs(arguments);

        if (arguments != nil){
//            if ((fileMonitor() != true) && (processMonitor() != true)){
//                goto bail;
//            }
            
            if (fileMonitor() != true){
                goto bail;
            }
            
            if (processMonitorr() != true){
                goto bail;
            }
//            printf("%s\n", [attack UTF8String]);
        }
        
        
        [[NSRunLoop currentRunLoop] run];
        
    }
    
bail:
        
    return status;
}

BOOL processArgs(NSArray* arguments){
    BOOL validArgs = YES;
    NSUInteger index = 0;
    
    skipSystem = [arguments containsObject:@"-skipSystem"];
    skipRedCan = [arguments containsObject:@"-skipRedCan"];
    printJSON = [arguments containsObject:@"-printJSON"];
    all = [arguments containsObject:@"-all"];
    
    index = [arguments indexOfObject:@"keylog"];
    if(NSNotFound != index){
            attack = arguments[index];
//            attack = [arguments objectAtIndex:index];
    }
    
    NSLog(@"attack : %@", attack);
    printf("SkipSystem : %s\n", skipSystem ? "true" : "false");

//    if(arguments.count > 1){
//        attack = arguments[1];
//            NSLog(@"Array: %@", arguments);
//            printf("Count: %d\n", arguments.count);
//            NSLog(@"%@", arguments[5]);
//    }
    
//    index = [arguments indexOfObject:@"attack"];
//    if(NSNotFound != index)
//    {
//        //inc
//        index++;
//        
//        //sanity check
//        // make sure name comes after
//        if(index >= arguments.count)
//        {
//            //invalid
//            validArgs = NO;
//            
//            //bail
//            goto bail;
//        }
//        
//        //grab filter name
//        attack = [arguments objectAtIndex:index];
//    }
    


bail:
    
    return validArgs;
}


BOOL fileMonitor(){
    
    es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_RENAME};

    FileMonitor* monitor = [[FileMonitor alloc] init];
    
    FileCallbackBlock block = ^(File* file)
    {
        
        if((YES == skipSystem) && (YES == file.process.isPlatformBinary.boolValue))
        {
            return;
        }
        
//        Red Canary Mac Monitor
        if(YES == skipRedCan){
            if((YES == [file.process.name isEqualToString:@"com.redcanary.agent.securityextension"]) || (YES == [file.process.name isEqualToString:@"com.crowdstrike.falcon.Agent"]) || (YES == [file.process.name isEqualToString:@"Red Canary Mac Monitor"])){
                return;
            }
        }
        
//        [arg1 isEqualToString:@"help"]
        if([attack isEqualToString:@"keylog"]){
//            printf("in");
            if( (YES != [file.sourcePath hasSuffix:@"IOHIDLib"]) &&
               (YES != [file.destinationPath hasSuffix:@"IOHIDLib"]))
            {
                //ignore
                return;
            }
            else{
                printf("IOC : Keylog  detected\n");
                printf("%s\n\n", prettifyJSON(file.description).UTF8String);
            }
        }
        
        if(AS_Ioc_Count == 2){
            if([file.destinationPath hasSuffix:@"login.keychain-db"] == YES){
                AS_Ioc_Count = 3;
                printf("Atomic Stealer Detected (3/3)\n\n");
                printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                return;
            }
        }
        
        if(LB_Ioc_Count == 0){
            if(file.event == ES_EVENT_TYPE_NOTIFY_RENAME){
//                printf("%s\n", prettifyJSON(file.description).UTF8String);
                if([file.destinationPath hasSuffix:@".lockbit"] == YES){
                    LB_Ioc_Count = 1;
                    printf("Lockbit Detected (1/2)\n\n");
                    printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                    return;
                }
            }
            
            else{
                if(YES == printJSON){
//                    printf("FILE\n");
//                    printf("%s\n", prettifyJSON(file.description).UTF8String);
    //                printf("==================");
    //                printf("%s\n\n", file.description.UTF8String);
                }
                else{
//                    printf("FILE\n");
//                    printf("%s\n", prettifyJSON(file.description).UTF8String);
    //                printf("%s\n\n", file.description.UTF8String);
                }
            }
        }
        
//        if(GM_Ioc_Count == 0){
            if(file.event == ES_EVENT_TYPE_NOTIFY_CREATE){
                if(([file.destinationPath rangeOfString:@"root"].location != NSNotFound) && ([file.destinationPath rangeOfString:@"CorelDRAW"].location != NSNotFound)){
                    GM_Ioc_Count = 1;
                    printf("Gimick Detected\n Malicious Folder Created\n\n");
                    printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                }
            }
//        }
        
        
//        if(GM_Ioc_Count == 1){
            if(file.event == ES_EVENT_TYPE_NOTIFY_CREATE){
                if(YES == [file.destinationPath isEqualToString:@"/Library/LaunchDaemons/.dat.nosyns2638.RKoEMI"]){
                    GM_Ioc_Count = 2;
                    printf("Gimick Detected\n Launch Daemons Created\n\n");
                    printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                }
            }
            
//        }
        
        
//        if(GM_Ioc_Count == 2){
            if(file.event == ES_EVENT_TYPE_NOTIFY_RENAME){
                if(YES == [file.destinationPath hasPrefix:@"/Library/LaunchDaemons/com.CorelDRAW.va.plist"]){
                    GM_Ioc_Count = 3;
                    printf("Gimick Detected\n Launch Daemons Renamed\n\n");
                    printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                }
            }
//        }
        
//        if(VPN_Ioc_Count == 0){
            if(file.event == ES_EVENT_TYPE_NOTIFY_CREATE){
                if(YES == [file.destinationPath hasSuffix:@".androids"]){
//                    VPN_Ioc_Count = 1;
                    printf("VPN Detected Trojan\n Creation Of Hidden Folder\n\n");
                    printf("File Destination Path : %s\n", [file.destinationPath UTF8String]);
                    printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                    return;
                }
            }
//        }
        


//        else if(VPN_Ioc_Count == 2){
            if(file.event == ES_EVENT_TYPE_NOTIFY_CREATE){
                if((YES == [file.destinationPath hasSuffix:@"softwareupdated"]) || (YES == [file.destinationPath hasSuffix:@"covid"])){
//                    VPN_Ioc_Count = 3;
                    printf("VPN Detected Trojan\n Creation of Malicious File\n\n");
                    printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                    return;
                }
            }
//        }
        
        if (YES == all){
//            printf("FILE\n");
//            printf("%s\n", prettifyJSON(file.description).UTF8String);
        }
        
//        if(LB_Ioc_Count == 1){
//            if(file.event == ES_EVENT_TYPE_NOTIFY_CREATE){
//                if([file.destinationPath rangeOfString:@"restore"])
//            }
//        }
    };
    return [monitor start:events count:sizeof(events)/sizeof(events[0]) csOption:csStatic callback:block];
}

BOOL processMonitorr()
{
    //(process) events of interest
    es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT, ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN};
    
    //init monitor
//    ProcessMonitor* procMon = [[ProcessMonitor alloc] init];
    ProcessMonitorr* procMonn = [[ProcessMonitorr alloc] init];
    
    //define block
    // automatically invoked upon process events
    ProcessCallbackBlock block = ^(Process22* process)
    {
        //do thingz
        // e.g. process.event has event (exec, fork, exit)
        // for now, we just print out the event and process object

//        if(process.event == ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN){
//            NSLog(@"Client Class %s", process.userClientClass);
//        }
//        if(process. == 3){
//            printf("es");
//        }
        
        //ingore apple?
        if( (YES == skipSystem) &&
            (YES == process.isPlatformBinary.boolValue))
        {
            //ignore
            return;
        }
        
        //filter
        // and no match? skip
        if(0 != filterBy.length)
        {
            //check file paths & process
            if(YES != [process.path hasSuffix:filterBy])
            {
                //ignore
                return;
            }
        }
    
        
        if (YES == all){
            printf("PROCESStq : \n");
            printf("%s\n\n", prettifyJSON(process.description).UTF8String);
            
            printf("=================================== : \n");
            
            printf("%s\n\n", process.description.UTF8String);
        }
        

        
        //pretty print?
        if(YES == printJSON)
        {
//            printf("PROCESStq : \n");
//            printf("%s\n\n", process.description.UTF8String);
//            printf("==================");
//            printf("%s\n\n", prettifyJSON(process.description).UTF8String);
//            printf("%s\n\n", prettifyJSON(process.arguments).UTF8String);
        }
        else
        {
//            printf("IN2");
            //output
//            printf("PROCESS\n");
//            printf("%s\n\n", process.description.UTF8String);
//            NSLog(@"%@\n\n", process.arguments);
        }
        
        
//        ATOMIC STEALER
        if(AS_Ioc_Count == 0){
            if((YES == [process.name isEqualToString:@"osascript"])&&(process.arguments.count > 2)){
                NSString *ioc1 = process.arguments[2];

                if(([ioc1 rangeOfString:@"password"].location != NSNotFound) && ([ioc1 rangeOfString:@"display dialog"].location != NSNotFound)){
                    
                    AS_Pid = process.ppid;
                    
                    AS_Ioc_Count = 1;
    //                NSLog(@"true");
//                    NSLog(@"Process name : %@\n", process.name);
//                    NSLog(@"Count : %d\n", AS_Ioc_Count);
//                    NSLog(@"PID ioc : %d\n", AS_Pid);
                    
//                    printf("PROCESS\n");
                    printf("Atomic Stealer Detected (1/3)\n\n");
                    printf("%s\n\n\n", prettifyJSON(process.description).UTF8String);
                    return;
                }
            }
        }

        
        if(AS_Ioc_Count == 1){
            if(YES == [process.name isEqualToString:@"dscl"] && (process.arguments.count > 2) && (AS_Pid == process.ppid)){
                NSLog(@"dscl");

                NSString *ioc1 = process.arguments[1];
                NSString *ioc2 = process.arguments[2];
                
                if(([ioc1 rangeOfString:@"Local"].location != NSNotFound) && ([ioc1 rangeOfString:@"Default"].location != NSNotFound) && ([ioc2 rangeOfString:@"-authonly"].location != NSNotFound)){
//                    NSLog(@"Local Default");
                    AS_Ioc_Count = 2;
//                    printf("PROCESS\n");
                    printf("Atomic Stealer Detected (2/3)\n\n");
                    printf("%s\n\n\n", prettifyJSON(process.description).UTF8String);
                    return;
                }
            }
        }
        
        
//        if(VPN_Ioc_Count == 1){
            if(process.event == ES_EVENT_TYPE_NOTIFY_EXEC){
                for(NSString* string in process.arguments){
                    if([string rangeOfString:@"46.137.201.254"].location != NSNotFound){
                        printf("VPN Trojan Detected\n Access to Malicious IP \n\n");
                        printf("%s\n\n\n", prettifyJSON(process.description).UTF8String);
                        break;
                    }
                    else if([string rangeOfString:@"com.apple.softwareupdate.plist"].location != NSNotFound){
                        printf("VPN Trojan Detected\n launch agent created\n\n");
                        printf("%s\n\n\n", prettifyJSON(process.description).UTF8String);
                        break;
                    }
                }
                return;
            }
//        }
        
        if(process.event == ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN){
            if([process.userClientClass rangeOfString:@"IOHIDLibUserClient"].location != NSNotFound){
                printf("Keylogger Detected\n IOHDILib Process detected \n\n");
                printf("%s\n\n\n", prettifyJSON(process.description).UTF8String);
                return;
            }
        }
        
        
    };
        
    //start monitoring
    // pass in events, count, and callback block for events
//    return [procMon start:events count:sizeof(events)/sizeof(events[0]) csOption:csStatic parseEnv:parseEnv callback:block];
    return [procMonn start:events count:sizeof(events)/sizeof(events[0]) csOption:csStatic parseEnv:parseEnv callback:block];
    return false;
}

NSString* prettifyJSON(NSString* output)
{
    // Data
    NSData* data = nil;
    
    // Error
    NSError* error = nil;
    
    // Object
    id object = nil;
    
    // Pretty data
    NSData* prettyData = nil;
    
    // Pretty string
    NSString* prettyString = nil;
    
    // Replace problematic newlines and other special characters
    NSString *correctedOutput = [output stringByReplacingOccurrencesOfString:@"\n" withString:@"\\n"];
//    correctedOutput = [correctedOutput stringByReplacingOccurrencesOfString:@"\t" withString:@"\\t"];
//    correctedOutput = [correctedOutput stringByReplacingOccurrencesOfString:@"\r" withString:@"\\r"];
    
    // Convert to data
    data = [correctedOutput dataUsingEncoding:NSUTF8StringEncoding];
   
    // Convert to JSON
    @try
    {
        // Serialize
        object = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
        if (nil == object)
        {
            // Bail
            goto bail;
        }
        
        // Convert to pretty data
        prettyData = [NSJSONSerialization dataWithJSONObject:object options:NSJSONWritingPrettyPrinted error:&error];
        if (nil == prettyData)
        {
            // Bail
            goto bail;
        }
    }
    // Ignore exceptions (here)
    @catch (NSException *exception)
    {
        // Bail
        goto bail;
    }
    
    // Convert to string
    prettyString = [[NSString alloc] initWithData:prettyData encoding:NSUTF8StringEncoding];
   
bail:
    
    // Error?
    if (nil == prettyString)
    {
        // Init error
        prettyString = @"{\"error\" : \"failed to convert output to JSON\"}";
    }
    
    return prettyString;
}









