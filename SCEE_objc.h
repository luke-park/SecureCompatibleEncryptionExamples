#import <Foundation/Foundation.h>
#import "SCEE.h"

@interface SCEE : NSObject

+ (int)encryptString:(NSString*)plaintext withPassword:(NSString*)password into:(NSString**)ciphertext;
+ (int)decryptString:(NSString*)ciphertext withPassword:(NSString*)password into:(NSString**)plaintext;
+ (int)encrypt:(NSData*)plaintext withKey:(NSData*)key into:(NSData**)dataout;
+ (int)decrypt:(NSData*)ciphertext withKey:(NSData*)key into:(NSData**)dataout;

@end
