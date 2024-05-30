//
//  main.m
//  SkripsiTesting
//
//  Created by Jeremy Christopher on 02/04/24.
//

#import "main.h"
#import "FileMonitor.h"
#import "ProcessMonitor.h"

int main(int argc, const char * argv[]) {
    
    //return var
    int status = -1;
    
    @autoreleasepool {
        NSArray* arguments = nil;
        
        arguments = [[NSProcessInfo processInfo] arguments];
        processArgs(arguments);

        if (arguments != nil){
            if (fileMonitor() != true && processMonitor() != true){
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
    
    es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_CLOSE};
    
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
            printf("in");
            if( (YES != [file.sourcePath hasSuffix:@"IOHIDLib"]) &&
               (YES != [file.destinationPath hasSuffix:@"IOHIDLib"]))
            {
                //ignore
                return;
            }
            else{
                printf("IOC : Keylog  detected\n");
                printf("%s\n\n", file.description.UTF8String);
            }
        }
        else{
            if(YES == printJSON){
                printf("%s\n", prettifyJSON(file.description).UTF8String);
            }
            else{
                printf("%s\n\n", file.description.UTF8String);
            }
            
            
        }
        
    };
    return [monitor start:events count:sizeof(events)/sizeof(events[0]) csOption:csStatic callback:block];
}

BOOL processMonitor()
{
    //(process) events of interest
    es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT};
    
    //init monitor
    ProcessMonitor* procMon = [[ProcessMonitor alloc] init];
    
    //define block
    // automatically invoked upon process events
    ProcessCallbackBlock block = ^(Process2* process)
    {
        //do thingz
        // e.g. process.event has event (exec, fork, exit)
        // for now, we just print out the event and process object
        
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
    
        //pretty print?
        if(YES == printJSON)
        {
            //make me pretty!
            printf("%s\n\n", prettifyJSON(process.description).UTF8String);
        }
        else
        {
            //output
            printf("%s\n\n", process.description.UTF8String);
        }
    };
        
    //start monitoring
    // pass in events, count, and callback block for events
    return [procMon start:events count:sizeof(events)/sizeof(events[0]) csOption:csStatic parseEnv:parseEnv callback:block];
    return false;
}

//prettify JSON
NSString* prettifyJSON(NSString* output)
{
    //data
    NSData* data = nil;
    
    //error
    NSError* error = nil;
    
    //object
    id object = nil;
    
    //pretty data
    NSData* prettyData = nil;
    
    //pretty string
    NSString* prettyString = nil;
    
    //covert to data
    data = [output dataUsingEncoding:NSUTF8StringEncoding];
   
    //convert to JSON
    // wrap since we are serializing JSON
    @try
    {
        //serialize
        object = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
        if(nil == object)
        {
            //bail
            goto bail;
        }
        
        //covert to pretty data
        prettyData = [NSJSONSerialization dataWithJSONObject:object options:NSJSONWritingPrettyPrinted error:&error];
        if(nil == prettyData)
        {
            //bail
            goto bail;
        }
    }
    //ignore exceptions (here)
    @catch(NSException *exception)
    {
        //bail
        goto bail;
    }
    
    //convert to string
    // note, we manually unescape forward slashes
    prettyString = [[[NSString alloc] initWithData:prettyData encoding:NSUTF8StringEncoding] stringByReplacingOccurrencesOfString:@"\\/" withString:@"/"];
   
bail:
    
    //error?
    if(nil == prettyString)
    {
        //init error
        prettyString = @"{\"error\" : \"failed to convert output to JSON\"}";
    }
    
    return prettyString;
}
