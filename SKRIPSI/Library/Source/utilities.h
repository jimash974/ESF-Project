#ifndef utilities_h
#define utilities_h

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>

//convert es_string_token_t to string
NSString* convertStringToken(es_string_token_t* stringToken);
//convert environment variable string to two separate strings representing a key and a value
void convertEnvironmentVariableStringToKeyValue(NSString *env, NSString **key, NSString **value);

#endif /* utilities_h */
