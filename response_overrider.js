Java.perform(function(){
    const RequestInterceptor = Java.use("com.anghami.ghost.api.config.RequestInterceptor");
    const SignatureUtils = Java.use("com.anghami.ghost.utils.SignatureUtils");
    const DeviceUtils = Java.use("com.anghami.ghost.utils.DeviceUtils")
    const EncryptionType = Java.use("com.anghami.ghost.api.config.RequestInterceptor$EncryptionType");
    const Ghost = Java.use("com.anghami.ghost.Ghost");
    const Signature = Java.use("android.content.pm.Signature")
    const MessageDigest = Java.use("java.security.MessageDigest")
    const Base64 = Java.use("android.util.Base64")

    const RequestBody = Java.use("okhttp3.RequestBody");
    const buffer = Java.use("okio.c");
    const StandardCharsets = Java.use("java.nio.charset.StandardCharsets");
    const String = Java.use('java.lang.String');
    const ByteArray = Java.use('[B')


    const intercept = RequestInterceptor.intercept;
    const generateToken = RequestInterceptor.generateToken;
    const signRequest = SignatureUtils.signRequest;
    const getDeviceId = DeviceUtils.getDeviceId;
    const decodeResponse = RequestInterceptor.decodeResponse
    const encodeRequest = RequestInterceptor.encodeRequest

    // let encryption_type = EncryptionType.get("authenticate.view")
    // console.log(encryption_type.a(1732319415))

    // SignatureUtils.signRequest.implementation = function (builder, bArr){
    //     console.log('------------------------sign------------------------')
    //     console.log(bArr);
    //     signRequest.apply(this, arguments);
    // }

    // let session_manager = Ghost.getSessionManager().getAppContext().getPackageManager().getPackageInfo(Ghost.getSessionManager().getAppContext().getPackageName(), 64).signatures
    // console.log("Signature:", session_manager.value[0])
    // const signature = Java.cast(session_manager.value[0], Signature)
    // console.log(signature.toByteArray())

    // const getAppSignature = SignatureUtils.getAppSignature;
    //
    // SignatureUtils.getAppSignature.overload('java.lang.String', '[B').implementation = function(key, arr){
    //     const signatures = Ghost.getSessionManager().getAppContext().getPackageManager().getPackageInfo(Ghost.getSessionManager().getAppContext().getPackageName(), 64).signatures
    //     const signature = Java.cast(signatures.value[0], Signature);
    //     const message_digest = MessageDigest.getInstance("SHA")
    //     message_digest.update(signature.toByteArray())
    //     const str2 = Java.use('java.lang.String').$new(Base64.encode(message_digest.digest(), 0)) + key;
    //
    //
    //     let byteArray = [] // [88,-110,-88,-18,119,81,-21,-3,102,-116,-6,90,-104,64,122,100,0,89,124,81,-61,23,71,113,11,-41,-55,-40,43,19,-75,54];
    //     for (let i = 0; i < str2.length; i++) {
    //         byteArray.push(str2.charCodeAt(i));
    //     }
    //
    //     byteArray = Java.array('byte', byteArray)
    //
    //     console.log(byteArray)
    //     const message_digest_2 = MessageDigest.getInstance('SHA-256')
    //     message_digest_2.update(byteArray, 0, byteArray.length);
    //     message_digest_2.update(arr);
    //     const result = SignatureUtils.convertToHex.apply(this, [message_digest_2.digest()]);
    //     console.log(result);
    //     return result;
    //     return getAppSignature.apply(this, [key, arr]);
    // }
    //
    // SignatureUtils.signRequest.overload('okhttp3.Request$Builder', '[B').implementation = function(builder, arr){
    //     let uuid = "af9e36f0-b49f-4fe7-9ba5-ca6361ed79b3";
    //     builder.header('X-ANGH-APP-RGSIG', SignatureUtils.getAppSignature(uuid, arr)).header("X-ANGH-APP-SALT", uuid);
    // }


    // RequestInterceptor.generateToken.implementation = function (x, y){
    //     let results = generateToken.apply(this, [x, y]);
    //     console.log(results, x, y)
    //     return results;
    // }
    //
    // RequestInterceptor.decodeResponse.implementation = function(bArr, bArr2){
    //     console.log("Decryption Key: ", bArr2)
    //     return decodeResponse.apply(this, arguments);
    // }
    //
    // RequestInterceptor.encodeRequest.implementation = function (bArr, bArr2){
    //     console.log("Encryption Key: ", bArr2)
    //     return encodeRequest.apply(this, arguments);
    // }
    // RequestInterceptor.intercept.implementation = function (chain){
        // const request = chain.request();
        // console.log(request.url().toString())
        // if (request.url() == "https://coussa.anghami.com/rest/v1/authenticate.view?output=jsonhp"){
        //     console.log('------------------------------------------------------')
        //     console.log(request.url())
        //     console.log(request.headers())

        //     console.log('------------------------------------------------------')
        // }
        // let c = buffer.$new();
        // request.body()?.writeTo(c);
        // let body = c.r0()
        // // body = String.$new(body, StandardCharsets.UTF_8.value);
        // c.close();
        // console.log('-------------------------body---------------------------')
        // console.log(body)
        // return intercept.apply(this, arguments);
    // }
})