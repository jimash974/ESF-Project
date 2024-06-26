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
            if (fileMonitor() != true){
                goto bail;
            }
            
            if (processMonitorr() != true){
                goto bail;
            }
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
        
//        ATOMIC STEALER
            if(([file.destinationPath hasSuffix:@"login.keychain-db"] == YES) && (![file.process.isPlatformBinary boolValue])){
                printf("Atomic Stealer Detected\nAcess To Logiin Keychain File\n\n");
                printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                return;
            }
        
        
//        LOCKBIT
            if(file.event == ES_EVENT_TYPE_NOTIFY_RENAME){
                if([file.destinationPath hasSuffix:@".lockbit"] == YES){
                    LB_Pid = file.process.pid;
                    printf("Lockbit Detected\nLockBit Extension detected\n\n");
                    printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                    return;
                }
            }
        
//        LOCKBIT
        if(file.event == ES_EVENT_TYPE_NOTIFY_CREATE){
//            printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
            if(([file.destinationPath rangeOfString:@"Restore"].location != NSNotFound) && (LB_Pid == file.process.pid)){
                printf("Lockbit Detected\nCreation of restore file\n\n");
                printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                return;
            }
        }
        
//        GIMICK
            if(file.event == ES_EVENT_TYPE_NOTIFY_CREATE){
                if((([file.destinationPath rangeOfString:@"root"].location != NSNotFound) && ([file.destinationPath rangeOfString:@"CorelDRAW"].location != NSNotFound)) && (![file.process.isPlatformBinary boolValue])){
                    printf("Gimick Detected\nMalicious Folder Created\n\n");
                    printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                }
            }
        
//        GIMICK
            if(file.event == ES_EVENT_TYPE_NOTIFY_CREATE){
                if((YES == [file.destinationPath isEqualToString:@"/Library/LaunchDaemons/.dat.nosyns2638.RKoEMI"]) && (![file.process.isPlatformBinary boolValue])){
                    printf("Gimick Detected\nLaunch Daemons Created\n\n");
                    printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                }
            }
        
//        GIMICK
            if(file.event == ES_EVENT_TYPE_NOTIFY_RENAME){
                if((YES == [file.destinationPath hasPrefix:@"/Library/LaunchDaemons/com.CorelDRAW.va.plist"]) && (![file.process.isPlatformBinary boolValue])){
                    printf("Gimick Detected\nLaunch Daemons Renamed\n\n");
                    printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                }
            }
        
//        VPN TROJAN
            if(file.event == ES_EVENT_TYPE_NOTIFY_CREATE){
                if(YES == [file.destinationPath hasSuffix:@".androids"]){
                    printf("VPN Trojan Detected\nCreation Of Hidden Folder\n\n");
                    printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                    return;
                }
            }
        
//        VPN TOJAN
            if(file.event == ES_EVENT_TYPE_NOTIFY_CREATE){
                if((YES == [file.destinationPath hasSuffix:@"softwareupdated"]) || (YES == [file.destinationPath hasSuffix:@"covid"])){
                    printf("VPN Detected Trojan\nCreation of Malicious File\n\n");
                    printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
                    return;
                }
            }
        
//        KEYLOGGER
        if(([file.destinationPath hasSuffix:@"IOHIDLib.plugin"] == YES) && (![file.process.isPlatformBinary boolValue])){
            printf("Keylogger Detected\nAccess to IOHIDLib.plugin\n\n");
            printf("%s\n\n\n", prettifyJSON(file.description).UTF8String);
            return;
        }
        
        if (YES == all){
            printf("FILE\n");
            printf("%s\n", prettifyJSON(file.description).UTF8String);
        }
    
    };
    return [monitor start:events count:sizeof(events)/sizeof(events[0]) csOption:csStatic callback:block];
}

BOOL processMonitorr()
{
    //(process) events of interest
    es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT, ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN};
    
    //init monitor
    ProcessMonitorr* procMonn = [[ProcessMonitorr alloc] init];
    
    //define block
    ProcessCallbackBlock block = ^(Process22* process)
    {
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
            printf("PROCESS : \n");
            printf("%s\n\n", prettifyJSON(process.description).UTF8String);
        }
        
//        ATOMIC STEALER
            if((YES == [process.name isEqualToString:@"osascript"])&&(process.arguments.count > 2)){
                NSString *ioc1 = process.arguments[2];

                if(([ioc1 rangeOfString:@"password"].location != NSNotFound) && ([ioc1 rangeOfString:@"display dialog"].location != NSNotFound)){
                    
                    AS_Pid = process.ppid;
                    printf("Atomic Stealer Detected\nOssascript usage\n\n");
                    printf("%s\n\n\n", prettifyJSON(process.description).UTF8String);
                    return;
                }
            }

//        ATOMIC STEALER
            if(YES == [process.name isEqualToString:@"dscl"] && (process.arguments.count > 2) && (AS_Pid == process.ppid)){
                bool ioc1 = false;
                bool ioc2 = false;
                
                for(NSString* string in process.arguments){
                    if([string rangeOfString:@"Local/Default"].location != NSNotFound){
                        ioc1 = true;
                    }
                    else if ([string rangeOfString:@"-authonly"].location != NSNotFound){
                        ioc2 = true;
                    }
                    
                    if(ioc1 && ioc2){
                        printf("Atomic Stealer Detected\nAccount Validation using dscl\n\n");
                        printf("%s\n\n\n", prettifyJSON(process.description).UTF8String);
                        break;
                    }
                }
            }
        
//        VPN
            if(process.event == ES_EVENT_TYPE_NOTIFY_EXEC){
                for(NSString* string in process.arguments){
                    if([string rangeOfString:@"46.137.201.254"].location != NSNotFound){
                        printf("VPN Trojan Detected\n Access to Malicious IP \n\n");
                        printf("%s\n\n\n", prettifyJSON(process.description).UTF8String);
                        break;
                    }
                    else if([string rangeOfString:@"com.apple.softwareupdate.plist"].location != NSNotFound){
                        printf("VPN Trojan Detected\nLaunch agent created\n\n");
                        printf("%s\n\n\n", prettifyJSON(process.description).UTF8String);
                        break;
                    }
                }
                return;
            }
        
//        KEYLOGGER
        if(process.event == ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN){

            if((([process.userClientClass rangeOfString:@"IOHIDLibUserClient"].location != NSNotFound) || ([process.userClientClass rangeOfString:@"IOHIDParamUserClient"].location != NSNotFound)) && (![process.isPlatformBinary boolValue])){
                printf("Keylogger Detected\nIOHDILibUserClient Process detected \n\n");
                printf("%s\n\n\n", prettifyJSON(process.description).UTF8String);
                return;
            }
        }
    };
        
    //start monitoring
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









