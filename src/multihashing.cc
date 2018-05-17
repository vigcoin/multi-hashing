#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scryptn.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "cryptonight.h"
    #include "x13.h"
    #include "nist5.h"
    #include "sha1.h"
    #include "x15.h"
	#include "fresh.h"
}

#include "boolberry.h"

using namespace node;
using namespace v8;

void except(const char* msg) {
    Isolate* isolate = Isolate::GetCurrent();
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, msg)));
}

void quark(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    quark_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}

void x11(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}

void scrypt(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();

    if (args.Length() < 3) {
        except("You must provide buffer to hash, N value, and R value");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    Local<Number> numn = args[1]->ToNumber(isolate);
    unsigned int nValue = numn->Value();
    Local<Number> numr = args[2]->ToNumber(isolate);
    unsigned int rValue = numr->Value();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    scrypt_N_R_1_256(input, output, nValue, rValue, input_len);
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, output));
}

void scryptn(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();

    if (args.Length() < 2) {
        except("You must provide buffer to hash and N factor.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    Local<Number> num = args[1]->ToNumber(isolate);
    unsigned int nFactor = num->Value();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    //unsigned int N = 1 << (getNfactor(input) + 1);
    unsigned int N = 1 << nFactor;

    scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, output));
}

void keccak(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];

    unsigned int dSize = Buffer::Length(target);

    keccak_hash(input, output, dSize);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}

void bcrypt(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];

    bcrypt_hash(input, output);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}

void skein(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);
    
    skein_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}

void groestl(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    groestl_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}


void groestlmyriad(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    groestlmyriad_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}

void blake(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    blake_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}


void fugue(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    fugue_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}


void qubit(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    qubit_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}


void hefty1(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    hefty1_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}

void shavite3(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    shavite3_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}

void cryptonight(const FunctionCallbackInfo<Value>& args) {
    bool fast = false;
    size_t variant = 0;

    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }
    
    if (args.Length() >= 2) {
        if (args[1]->IsBoolean()) {
            fast = args[1]->ToBoolean()->BooleanValue();
        } else if (args[1]->IsUint32()) {
            variant = args[1]->ToUint32()->Uint32Value();
        } else {
            return except("Argument 2 should be a boolean or uint32_t");
        }
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    if (fast) {
        cryptonight_fast_hash(input, output, input_len);
    } else {
         if (variant > 0 && input_len < 43) {
            return except("Argument must be 43 bytes for monero variant 1+");
         }
            
        cryptonight_hash(input, output, input_len, variant);
    }

    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}

void x13(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x13_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}

void boolberry(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    
    if (args.Length() < 2) {
        except("You must provide two arguments.");
        return;
    }

    Local<Object> target = args[0]->ToObject();
    Local<Object> target_spad = args[1]->ToObject();
    uint32_t height = 1;

    if (!Buffer::HasInstance(target)) {
        except("Argument 1 should be a buffer object.");
        return;
    }

    if (!Buffer::HasInstance(target_spad)) {
        except("Argument 2 should be a buffer object.");
        return;
    }

    if(args.Length() >= 3) {
        if(args[2]->IsUint32()) {
            height = args[2]->Uint32Value();
        } else {
            except("Argument 3 should be an unsigned integer.");
            return;
        }
    }

    char * input = Buffer::Data(target);
    char * scratchpad = Buffer::Data(target_spad);
    char output[32];

    uint32_t input_len = Buffer::Length(target);
    uint64_t spad_len = Buffer::Length(target_spad);

    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, output));
}

void nist5(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    nist5_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}

void sha1(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    sha1_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}

void x15(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x15_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}

void fresh(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) {
        except("You must provide one argument.");
        return;
    }

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target)) {
        except("Argument should be a buffer object.");
        return;
    }

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fresh_hash(input, output, input_len);
    args.GetReturnValue().Set(node::Buffer::Copy(Isolate::GetCurrent(), output, 32).ToLocalChecked());
}

void init(Local<Object> exports) {
    NODE_SET_METHOD(exports, "quark", quark);
    NODE_SET_METHOD(exports, "x11", x11);
    NODE_SET_METHOD(exports, "scrypt", scrypt);
    NODE_SET_METHOD(exports, "scryptn", scryptn);
    NODE_SET_METHOD(exports, "keccak", keccak);
    NODE_SET_METHOD(exports, "bcrypt", bcrypt);
    NODE_SET_METHOD(exports, "skein", skein);
    NODE_SET_METHOD(exports, "groestl", groestl);
    NODE_SET_METHOD(exports, "groestlmyriad", groestlmyriad);
    NODE_SET_METHOD(exports, "blake", blake);
    NODE_SET_METHOD(exports, "fugue", fugue);
    NODE_SET_METHOD(exports, "qubit", qubit);
    NODE_SET_METHOD(exports, "hefty1", hefty1);
    NODE_SET_METHOD(exports, "shavite3", shavite3);
    NODE_SET_METHOD(exports, "cryptonight", cryptonight);
    NODE_SET_METHOD(exports, "x13", x13);
    NODE_SET_METHOD(exports, "boolberry", boolberry);
    NODE_SET_METHOD(exports, "nist5", nist5);
    NODE_SET_METHOD(exports, "sha1", sha1);
    NODE_SET_METHOD(exports, "x15", x15);
    NODE_SET_METHOD(exports, "fresh", fresh);
}

NODE_MODULE(multihashing, init)
