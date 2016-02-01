
#ifndef oa_decrypt_h
#define oa_decrypt_h


#ifdef _WIN32
#    ifdef LIBRARY_EXPORTS
#        define LIBRARY_API __declspec(dllexport)
#    else
#        define LIBRARY_API __declspec(dllimport)
#    endif
#else
#    define LIBRARY_API
#endif

#ifdef  __cplusplus

extern  "C" {
#endif

typedef struct SignContext
{
    char *p;
    char result[512];
} SignContext;

LIBRARY_API void SignInit(SignContext *ctx, char *src);

LIBRARY_API void GenSignature(SignContext *ctx);

LIBRARY_API void a(char *s);

LIBRARY_API char* GetString();
    LIBRARY_API void CtoM(const char *src,const char *key,char *output);
#ifdef  __cplusplus
}
#endif
#endif


