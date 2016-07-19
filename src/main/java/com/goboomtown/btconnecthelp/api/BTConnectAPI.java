package com.goboomtown.btconnecthelp.api;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.location.Criteria;
import android.location.Location;
import android.location.LocationManager;
import android.util.Base64;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * Created by Larry Borsato on 2016-07-12.
 */
public class BTConnectAPI {

    public static String BTConnectAPIBaseURL   =  "https://api.goboomtown.com";
    public static String kEndpoint             = "/api/v2";

    private static BTConnectAPI shared_instance = null;

    private String  apiToken  = null;
    private String  apiSecret = null;

//    private static final Mac sha256_HMAC;
//    static {
//        try {
//            sha256_HMAC = Mac.getInstance("HmacSHA256");
//            sha256_HMAC.init(new javax.crypto.spec.SecretKeySpec(sharedInstance().apiSecret.getBytes("UTF-8"), "HmacSHA256"));
//        } catch (InvalidKeyException e) {
//            throw new ExceptionInInitializerError(e);
//        } catch (NoSuchAlgorithmException e) {
//            throw new ExceptionInInitializerError(e);
//        } catch (UnsupportedEncodingException e) {
//            throw new ExceptionInInitializerError(e);
//        }
//    }

    private static String encode(String data) throws Exception {
        Mac sha256_HMAC = null;
        String signature = null;
        try {
            sha256_HMAC = Mac.getInstance("HmacSHA256");
            sha256_HMAC.init(new javax.crypto.spec.SecretKeySpec(sharedInstance().apiSecret.getBytes("UTF-8"), "HmacSHA256"));
            signature = Base64.encodeToString(sha256_HMAC.doFinal(data.getBytes("UTF-8")), Base64.DEFAULT);
        } catch (InvalidKeyException e) {
            throw new ExceptionInInitializerError(e);
        } catch (NoSuchAlgorithmException e) {
            throw new ExceptionInInitializerError(e);
        } catch (UnsupportedEncodingException e) {
            throw new ExceptionInInitializerError(e);
        }
        return signature;
    }

    private BTConnectAPI(){
    }

    public static BTConnectAPI sharedInstance(){
        if( shared_instance == null){
//            synchronized( client ){
            shared_instance = new BTConnectAPI();
            shared_instance.apiToken  = null;
            shared_instance.apiSecret = null;
//            }
        }
        return shared_instance;
    }


    public static void setCredentials(String token, String secret)
    {
        sharedInstance().apiToken	= token;
        sharedInstance().apiSecret	= secret;
    }


    public static JSONObject extractXmppInformation(String xmppData)
    {
        // example payload, as returned in {{xmpp_data}} from an api/v2 issue response.
        // payload is a base64 encoded string of the IV concatenated with the AES 256 encrypted JSON encoded payload.
//        NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:xmppData options:0];
//
//        // decode the JSON to obtain the original payload
//        NSData *jsonData = [[self sharedInstance] AES256Decrypt:decodedData withKey:[self sharedInstance].apiSecret];
//        NSString *jsonString = [[[[NSString alloc] initWithData:jsonData encoding:NSASCIIStringEncoding] stringByReplacingOccurrencesOfString:@"\t" withString:@""] stringByReplacingOccurrencesOfString:@"\0" withString:@""];
//        jsonString = [jsonString stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
//        jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
//        NSError *jsonError;
//        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:jsonData
//        options:NSJSONReadingMutableContainers
//        error:&jsonError];
        return new JSONObject();
    }

    private static final int DEFAULT_TIMEOUT = 30;	// 30 seconds

//	private static final OkHttpClient client = new OkHttpClient();

    private static final OkHttpClient client = new OkHttpClient.Builder()
            .connectTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .build();

    public static void post(Context context, String uri, JSONObject jsonParams, Callback callback) {
        String requestUrl = String.format("%s%s", BTConnectAPIBaseURL, uri);
        Request request = new Request.Builder()
                .url(requestUrl)
                .headers(Headers.of(addHeaders(uri)))
                .post(RequestBody.create(MediaType.parse("application/json; charset=utf-8"), jsonParams.toString()))
                .build();

//		Log.d("RestClient", "POST " + requestUrl);
        client.newCall(request).enqueue(callback);
    }

    public static void get(Context context, String uri, Callback callback) {
        String requestUrl = String.format("%s%s", BTConnectAPIBaseURL, uri);
        Request request = new Request.Builder()
                .url(requestUrl)
                .headers(Headers.of(addHeaders(uri)))
                .build();

//		Log.d("RestClient", "GET " + requestUrl);

        client.newCall(request).enqueue(callback);
    }

    private static HashMap<String, String> addHeaders(String uri) {
        HashMap<String, String> headerMap = new HashMap<String, String>();

        String iso8601Date 			= iso8601Date();
        String canonicalizedResource = String.format("%s:%s", uri, iso8601Date);
        String signature 			= null;
        try {
            signature = encode(canonicalizedResource);
        } catch (Exception e) {
            e.printStackTrace();
        }

        headerMap.put("X-Boomtown-Date", iso8601Date);
        headerMap.put("X-Boomtown-Token", sharedInstance().apiToken);
        headerMap.put("X-Boomtown-Signature", signature);
        return headerMap;
    }

    private static String iso8601Date() {
        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZZZZZ");

        // Use UTC as the default time zone.
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

        Calendar c = Calendar.getInstance();
        return dateFormat.format(c.getTime());
    }


}
