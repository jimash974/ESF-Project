//#import "utilities.h"
//#import "ProcessMonitorr.h"
//
//#import <Foundation/Foundation.h>
//#import <EndpointSecurity/EndpointSecurity.h>
//
////endpoint client
//es_client_t* endpointClientPM = nil;
//
////pointer to function
//// responsibility_get_pid_responsible_for_pid()
//pid_t (*getRPID)(pid_t pid) = NULL;
//
//@implementation ProcessMonitorr
//
////start monitoring
//// pass in events of interest, count of said events, flag for codesigning, flag for environment variable collection, and callback
//-(BOOL)start:(es_event_type_t*)events count:(uint32_t)count csOption:(NSUInteger)csOption parseEnv:(BOOL)parseEnv callback:(ProcessCallbackBlock)callback
//{
//    
//    printf("in");
//    return false;
//    //flag
//    BOOL started = NO;
//    
//    //result
//    es_new_client_result_t result = 0;
//    
//    //sync
//    @synchronized (self)
//    {
//    
//    //create client
//    // callback invokes (user) callback for new processes
//    result = es_new_client(&endpointClientPM, ^(es_client_t *client, const es_message_t *message)
//    {
//        //new process event
//        Process22* process = nil;
//        
//        //init process obj
//        // do static check as well
//        process = [[Process22 alloc] init:(es_message_t* _Nonnull)message csOption:csOption parseEnv:parseEnv];
//        if(nil != process)
//        {
//            //invoke user callback
//            callback(process);
//        }
//    });
//        
//    //error?
////    if(ES_NEW_CLIENT_RESULT_SUCCESS != result)
////    {
////        //err msg
////        NSLog(@"ERROR: es_new_client() failedddd");
////        
////        //provide more info
////        switch (result) {
////                
////            //not entitled
////            case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
////                NSLog(@"ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: \"The caller is not properly entitled to connect\"");
////                break;
////                      
////            //not permitted
////            case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
////                NSLog(@"ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: \"The caller is not permitted to connect. They lack Transparency, Consent, and Control (TCC) approval form the user.\"");
////                break;
////                      
////            //not privileged
////            case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
////                NSLog(@"ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: \"The caller is not running as root\"");
////                break;
////                
////            default:
////                break;
////        }
////    
////        //bail
////        goto bail;
////    }
//    
//    //clear cache
//    if(ES_CLEAR_CACHE_RESULT_SUCCESS != es_clear_cache(endpointClientPM))
//    {
//        //err msg
//        NSLog(@"ERROR: es_clear_cache() failed");
//        
//        //bail
//        goto bail;
//    }
//    
//    //subscribe
//    if(ES_RETURN_SUCCESS != es_subscribe(endpointClientPM, events, count))
//    {
//        //err msg
//        NSLog(@"ERROR: es_subscribe() failed");
//        
//        //bail
//        goto bail;
//    }
//        
//    } //sync
//    
//    //happy
//    started = YES;
//    
//bail:
//    
//    return started;
//}
//
////stop
//-(BOOL)stop
//{
//    //flag
//    BOOL stopped = NO;
//    
//    //sync
//    @synchronized (self)
//    {
//        
//    //unsubscribe & delete
//    if(NULL != endpointClientPM)
//    {
//       //unsubscribe 
//       if(ES_RETURN_SUCCESS != es_unsubscribe_all(endpointClientPM))
//       {
//           //err msg
//           NSLog(@"ERROR: es_unsubscribe_all() failed");
//           
//           //bail
//           goto bail;
//       }
//       
//       //delete client
//       if(ES_RETURN_SUCCESS != es_delete_client(endpointClientPM))
//       {
//           //err msg
//           NSLog(@"ERROR: es_delete_client() failed");
//           
//           //bail
//           goto bail;
//       }
//       
//       //unset
//        endpointClientPM = NULL;
//       
//       //happy
//       stopped = YES;
//    }
//        
//    } //sync
//    
//bail:
//    
//    return stopped;
//}
//
//@end
