#import "SCEE_objc.h"

@implementation SCEE

+ (int)encryptString:(NSString*)plaintext withPassword:(NSString*)password into:(NSString**)ciphertext {
    const char* pt = [plaintext UTF8String];
    const char* pass = [password UTF8String];

    size_t ct_length = scee_crypt_string_get_length(strlen(pt), SCEE_CRYPT_ENCRYPT);
    unsigned char ct[ct_length];

    int r = scee_encrypt_string((unsigned char*)pt, strlen(pt), (unsigned char*)pass, strlen(pass), ct);
    if (r != SCEE_OK) { return r; }

    *ciphertext = [NSString stringWithUTF8String:(char*)ct];
    return SCEE_OK;
}
+ (int)decryptString:(NSString*)ciphertext withPassword:(NSString*)password into:(NSString**)plaintext {
    const char* ct = [ciphertext UTF8String];
    const char* pass = [password UTF8String];

    size_t t_length;
    size_t pt_length = scee_crypt_string_get_length(strlen(ct), SCEE_CRYPT_DECRYPT);
    unsigned char pt[pt_length];

    int r = scee_decrypt_string((unsigned char*)ct, strlen(ct), (unsigned char*)pass, strlen(pass), pt, &t_length);
    if (r != SCEE_OK) { return r; }

    *plaintext = [NSString stringWithUTF8String:(char*)pt];
    return SCEE_OK;
}
+ (int)encrypt:(NSData*)plaintext withKey:(NSData*)key into:(NSData**)dataout {
    uint8_t* pt = (uint8_t*)[plaintext bytes];
    uint8_t* k = (uint8_t*)[key bytes];
    size_t pt_length = [plaintext length];

    size_t ct_length = pt_length + SCEE_NONCE_LENGTH + SCEE_TAG_LENGTH;
    uint8_t ct[ct_length];
    int r = scee_encrypt(pt, pt_length, k, ct);
    if (r != SCEE_OK) { return r; }

    *dataout = [NSData dataWithBytes:ct length:ct_length];
    return SCEE_OK;
}
+ (int)decrypt:(NSData*)ciphertext withKey:(NSData*)key into:(NSData**)dataout {
    uint8_t* ct = (uint8_t*)[ciphertext bytes];
    uint8_t* k = (uint8_t*)[key bytes];
    size_t ct_length = [ciphertext length];

    size_t pt_length = ct_length - SCEE_NONCE_LENGTH - SCEE_TAG_LENGTH;
    uint8_t pt[pt_length];
    int r = scee_decrypt(ct, ct_length, k, pt);
    if (r != SCEE_OK) { return r; }

    *dataout = [NSData dataWithBytes:pt length:pt_length];
    return SCEE_OK;
}

@end
