//
//  main.m
//  SkripsiTesting
//
//  Created by Jeremy Christopher on 02/04/24.
//

#import "main.h"
#import "FileMonitor.h"

int main(int argc, const char * argv[]) {
    
    //return var
    int status = -1;
    
    @autoreleasepool {
        NSArray* arguments = nil;
        
        arguments = [[NSProcessInfo processInfo] arguments];
//        processArgs(arguments);
        if(arguments.count > 1){
            attack = arguments[1];
        }
        if (arguments != nil){
            if (monitor() != true){
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
    
    index = [arguments indexOfObject:@"keylog"];
    if(NSNotFound != index)
    {
        //inc
        index++;
        
        //sanity check
        // make sure name comes after
        if(index >= arguments.count)
        {
            //invalid
            validArgs = NO;
            
            //bail
            goto bail;
        }
        
        //grab filter name
        attack = [arguments objectAtIndex:index];
    }
    


bail:
    
    return validArgs;
}


BOOL monitor(){
    
    es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_CLOSE};
    
    FileMonitor* monitor = [[FileMonitor alloc] init];
    
    FileCallbackBlock block = ^(File* file)
    {
        
//        [arg1 isEqualToString:@"help"]
        if([attack isEqualToString:@"keylog"]){
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
            printf("%s\n\n", file.description.UTF8String);
        }
        
    };
    return [monitor start:events count:sizeof(events)/sizeof(events[0]) csOption:csStatic callback:block];
}
