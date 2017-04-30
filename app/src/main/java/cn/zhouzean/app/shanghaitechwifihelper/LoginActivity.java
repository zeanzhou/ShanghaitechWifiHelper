package cn.zhouzean.app.shanghaitechwifihelper;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.annotation.TargetApi;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.support.annotation.NonNull;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.app.LoaderManager.LoaderCallbacks;

import android.content.CursorLoader;
import android.content.Loader;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;

import android.os.Build;
import android.os.Bundle;
import android.provider.ContactsContract;
import android.text.TextUtils;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.inputmethod.EditorInfo;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.Switch;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Random;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonIOException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import android.app.AlertDialog;
import android.content.Context;
import android.widget.Toast;


import static android.Manifest.permission.READ_CONTACTS;

/**
 * A login screen that offers login via email/password.
 */
public class LoginActivity extends AppCompatActivity implements LoaderCallbacks<Cursor> {

    /**
     * Keep track of the login task to ensure we can cancel it if requested.
     */
    private UserLoginTask mAuthTask = null;

    // UI references.
    private Switch mRememberView;
    private Switch mAutoLoginView;
    private EditText mUsernameView;
    private EditText mPasswordView;
    private View mProgressView;
    private View mLoginFormView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        SharedPreferences preferences=getSharedPreferences("ShanghaitechWifiHelper-config", Context.MODE_PRIVATE);
        String username = preferences.getString("username", "");
        String password = preferences.getString("password", "");
        Boolean isRemember = preferences.getBoolean("isRemember", false);
        Boolean isAutoLogin = preferences.getBoolean("isAutoLogin", false);

        setContentView(R.layout.activity_login);
        // Set up the login form.
        mUsernameView = (EditText) findViewById(R.id.username);

        mPasswordView = (EditText) findViewById(R.id.password);
        mPasswordView.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            @Override
            public boolean onEditorAction(TextView textView, int id, KeyEvent keyEvent) {
                if (id == R.id.login || id == EditorInfo.IME_NULL) {
                    attemptLogin();
                    return true;
                }
                return false;
            }
        });
        mRememberView = (Switch) findViewById(R.id.remember_switch);
        mAutoLoginView = (Switch) findViewById(R.id.autologin_switch);

        mUsernameView.setText(username);
        mPasswordView.setText(password);
        mRememberView.setChecked(isRemember);
        mAutoLoginView.setChecked(isAutoLogin);

        mRememberView.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (!isChecked)
                    mAutoLoginView.setChecked(false);
                saveConfig();
            }
        });
        mAutoLoginView.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked)
                    mRememberView.setChecked(true);
                saveConfig();

            }
        });

        Button mConnectButton = (Button) findViewById(R.id.connect_button);
        mConnectButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View view) {
                attemptLogin();
            }
        });

        mLoginFormView = findViewById(R.id.login_form);
        mProgressView = findViewById(R.id.login_progress);
        if (isAutoLogin)
            attemptLogin();
    }

//    private void populateAutoComplete() {
//        if (!mayRequestContacts()) {
//            return;
//        }
//
//        getLoaderManager().initLoader(0, null, this);
//    }
//
//    private boolean mayRequestContacts() {
//        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
//            return true;
//        }
//        if (checkSelfPermission(READ_CONTACTS) == PackageManager.PERMISSION_GRANTED) {
//            return true;
//        }
//        if (shouldShowRequestPermissionRationale(READ_CONTACTS)) {
//            Snackbar.make(mUsernameView, R.string.permission_rationale, Snackbar.LENGTH_INDEFINITE)
//                    .setAction(android.R.string.ok, new View.OnClickListener() {
//                        @Override
//                        @TargetApi(Build.VERSION_CODES.M)
//                        public void onClick(View v) {
//                            requestPermissions(new String[]{READ_CONTACTS}, REQUEST_READ_CONTACTS);
//                        }
//                    });
//        } else {
//            requestPermissions(new String[]{READ_CONTACTS}, REQUEST_READ_CONTACTS);
//        }
//        return false;
//    }

    /**
     * Callback received when a permissions request has been completed.
     */
    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
//        if (requestCode == REQUEST_READ_CONTACTS) {
//            if (grantResults.length == 1 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
//                populateAutoComplete();
//            }
//        }
    }


    /**
     * Attempts to sign in or register the account specified by the login form.
     * If there are form errors (invalid email, missing fields, etc.), the
     * errors are presented and no actual login attempt is made.
     */
    private void attemptLogin() {
        if (mAuthTask != null) {
            return;
        }

        // Reset errors.
        mUsernameView.setError(null);
        mPasswordView.setError(null);

        // Store values at the time of the login attempt.
        String username = mUsernameView.getText().toString();
        String password = mPasswordView.getText().toString();

        boolean cancel = false;
        View focusView = null;

        // Check for a valid password, if the user entered one.
        if (TextUtils.isEmpty(password)) {
            mPasswordView.setError(getString(R.string.error_field_required));
            focusView = mPasswordView;
            cancel = true;
        }


        // Check for a valid email address.
        if (TextUtils.isEmpty(username)) {
            mUsernameView.setError(getString(R.string.error_field_required));
            focusView = mUsernameView;
            cancel = true;
        }

        if (cancel) {
            // There was an error; don't attempt login and focus the first
            // form field with an error.
            focusView.requestFocus();
        } else {
            // Show a progress spinner, and kick off a background task to
            // perform the user login attempt.


            saveConfig();
            // TODO: Enable WIFI Detection...
            cancel = true;
            WifiManager wifiManager = (WifiManager) LoginActivity.this.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wifiManager != null) {
                int wifiState = wifiManager.getWifiState();
                if (wifiState == wifiManager.WIFI_STATE_ENABLED) {
                    WifiInfo wifiInfo = wifiManager.getConnectionInfo();
                    String SSID = wifiInfo.getSSID();
                    if (SSID != "ShanghaiTech" && SSID != "guest") {
                        ShowMsg(this.getResources().getString(R.string.message_wifi_wrong_ssid), LoginActivity.this);
                    } else {
                        cancel = false;
                    }
                } else {
                    ShowMsgTurnOnWifi(LoginActivity.this, wifiManager);
                }
            } else {
                System.err.println("WIFI Manager is null!");
            }

            if (!cancel) {
                showProgress(true);
                mAuthTask = new UserLoginTask(username, password);
                mAuthTask.execute((Void) null);
            }

        }
    }

    /**
     * Shows the progress UI and hides the login form.
     */
    @TargetApi(Build.VERSION_CODES.HONEYCOMB_MR2)
    private void showProgress(final boolean show) {
        // On Honeycomb MR2 we have the ViewPropertyAnimator APIs, which allow
        // for very easy animations. If available, use these APIs to fade-in
        // the progress spinner.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB_MR2) {
            int shortAnimTime = getResources().getInteger(android.R.integer.config_shortAnimTime);

            mLoginFormView.setVisibility(show ? View.GONE : View.VISIBLE);
            mLoginFormView.animate().setDuration(shortAnimTime).alpha(
                    show ? 0 : 1).setListener(new AnimatorListenerAdapter() {
                @Override
                public void onAnimationEnd(Animator animation) {
                    mLoginFormView.setVisibility(show ? View.GONE : View.VISIBLE);
                }
            });

            mProgressView.setVisibility(show ? View.VISIBLE : View.GONE);
            mProgressView.animate().setDuration(shortAnimTime).alpha(
                    show ? 1 : 0).setListener(new AnimatorListenerAdapter() {
                @Override
                public void onAnimationEnd(Animator animation) {
                    mProgressView.setVisibility(show ? View.VISIBLE : View.GONE);
                }
            });
        } else {
            // The ViewPropertyAnimator APIs are not available, so simply show
            // and hide the relevant UI components.
            mProgressView.setVisibility(show ? View.VISIBLE : View.GONE);
            mLoginFormView.setVisibility(show ? View.GONE : View.VISIBLE);
        }
    }

    @Override
    public Loader<Cursor> onCreateLoader(int i, Bundle bundle) {
        return null;
    }
//        return new CursorLoader(this,
//                // Retrieve data rows for the device user's 'profile' contact.
//                Uri.withAppendedPath(ContactsContract.Profile.CONTENT_URI,
//                        ContactsContract.Contacts.Data.CONTENT_DIRECTORY), ProfileQuery.PROJECTION,
//
//                // Select only email addresses.
//                ContactsContract.Contacts.Data.MIMETYPE +
//                        " = ?", new String[]{ContactsContract.CommonDataKinds.Email
//                .CONTENT_ITEM_TYPE},
//
//                // Show primary email addresses first. Note that there won't be
//                // a primary email address if the user hasn't specified one.
//                ContactsContract.Contacts.Data.IS_PRIMARY + " DESC");
//    }

    @Override
    public void onLoadFinished(Loader<Cursor> cursorLoader, Cursor cursor) {
//        List<String> emails = new ArrayList<>();
//        cursor.moveToFirst();
//        while (!cursor.isAfterLast()) {
//            emails.add(cursor.getString(ProfileQuery.ADDRESS));
//            cursor.moveToNext();
//        }

//        addEmailsToAutoComplete(emails);
    }

    @Override
    public void onLoaderReset(Loader<Cursor> cursorLoader) {

    }

//    private void addEmailsToAutoComplete(List<String> emailAddressCollection) {
//        //Create adapter to tell the AutoCompleteTextView what to show in its dropdown list.
//        ArrayAdapter<String> adapter =
//                new ArrayAdapter<>(LoginActivity.this,
//                        android.R.layout.simple_dropdown_item_1line, emailAddressCollection);
//
//        mUsernameView.setAdapter(adapter);
//    }


//    private interface ProfileQuery {
//        String[] PROJECTION = {
//                ContactsContract.CommonDataKinds.Email.ADDRESS,
//                ContactsContract.CommonDataKinds.Email.IS_PRIMARY,
//        };
//
//        int ADDRESS = 0;
//        int IS_PRIMARY = 1;
//    }

    /**
     * Represents an asynchronous login/registration task used to authenticate
     * the user.
     */
    public class UserLoginTask extends AsyncTask<Void, Void, Boolean> {

        private final String mUsername;
        private final String mPassword;

        UserLoginTask(String username, String password) {
            mUsername = username;
            mPassword = password;
        }

        @Override
        protected Boolean doInBackground(Void... params) {
            final Boolean retVal = loginByPost(mUsername, mPassword);

//            for (String credential : DUMMY_CREDENTIALS) {
//                String[] pieces = credential.split(":");
//                if (pieces[0].equals(mUsername)) {
//                    // Account exists, return true if the password matches.
//                    return pieces[1].equals(mPassword);
//                }
//            }
            return retVal;
        }

        @Override
        protected void onPostExecute(final Boolean success) {
            mAuthTask = null;
            showProgress(false);
            System.out.println("success = "+success);
            if (success) {
                System.out.println("SUCCESS");
//                try {
//                    Thread.sleep(5000);
//                } catch (Exception e) {
//                    e.printStackTrace();
//                }
//                finish();
            } else {
//                mPasswordView.setError(getString(R.string.error_incorrect_password));
                mPasswordView.requestFocus();
            }
        }

        @Override
        protected void onCancelled() {
            mAuthTask = null;
            showProgress(false);
        }
    }
    public static String getRandomString(int length) { //length表示生成字符串的长度
        String base = "abcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }

    public Boolean loginByPost(String userName, String userPass) {
        Boolean retVal = false;
        String sessionID = getRandomString(32);
        try {
            // 请求的地址
            String spec = "https://controller1.net.shanghaitech.edu.cn:8445/PortalServer/Webauth/webAuthAction!login.action";
            // 根据地址创建URL对象
            URL url = new URL(spec);
            // 根据URL对象打开链接
            HttpURLConnection urlConnection = (HttpURLConnection) url
                    .openConnection();
            // 设置请求的方式
            urlConnection.setRequestMethod("POST");
            // 设置请求的超时时间
            urlConnection.setReadTimeout(5000);
            urlConnection.setConnectTimeout(5000);
            // 传递的数据
            String data = "userName=" + URLEncoder.encode(userName, "UTF-8")
                    + "&password=" + URLEncoder.encode(userPass, "UTF-8")
                    + "&hasValidateCode=" + "false"
                    + "&validCode=" + ""
                    + "&hasValidateNextUpdatePassword=" + "true"
                    ;

            // 设置请求的头
            urlConnection.setRequestProperty("Accept", "*/*");
            // 设置请求的头
            urlConnection.setRequestProperty("Content-Type",
                    "application/x-www-form-urlencoded");
            // 设置请求的头
            urlConnection.setRequestProperty("Cookie",
                    "JSESSIONID=" + sessionID);
            // 设置请求的头
            urlConnection
                    .setRequestProperty("User-Agent",
                            "ShanghaiTech_WIFI_Helper Android");
            urlConnection.setDoOutput(true); // 发送POST请求必须设置允许输出
            urlConnection.setDoInput(true); // 发送POST请求必须设置允许输入
            //setDoInput的默认值就是true
            //获取输出流
            OutputStream os = urlConnection.getOutputStream();
            os.write(data.getBytes());
            os.flush();
            if (urlConnection.getResponseCode() == 200) {

                // 获取响应的输入流对象
                InputStream is = urlConnection.getInputStream();
                // 创建字节输出流对象
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                // 定义读取的长度
                int len = 0;
                // 定义缓冲区
                byte buffer[] = new byte[1024];
                // 按照缓冲区的大小，循环读取
                while ((len = is.read(buffer)) != -1) {
                    // 根据读取的长度写入到os对象中
                    baos.write(buffer, 0, len);
                }
                // 释放资源
                is.close();
                baos.close();
                // 返回字符串
                final String result = new String(baos.toByteArray()).replace("null", "\"\""); // Avoid null
                System.out.println(result);

                JsonParser parser = new JsonParser();  //创建JSON解析器
                JsonObject object = (JsonObject) parser.parse(result);  //创建JsonObject对象
                System.out.println("message="+object.get("message").getAsString()); //将json数据转为为String型的数据
                System.out.println("success="+object.get("success").getAsBoolean()); //将json数据转为为boolean型的数据

                Boolean success = object.get("success").getAsBoolean();
                String message = object.get("message").getAsString();

                String dataStr = "";
                try {
                    dataStr = object.get("data").getAsString();
                } catch (Exception e) {
//                    e.printStackTrace();
                }
                System.out.println("dataStr = " + dataStr);
                if (message != "" && message.indexOf("token") < 0) {
                    // failed
                }
                else if (dataStr == "session_timeout" || object.get("sessionTimeOut").getAsBoolean()) {
                    message = "会话已超时";
                }
                else { // if (success)
                    Boolean portalAuth = object.get("data").getAsJsonObject().get("portalAuth").getAsBoolean();
                    Integer webPortalOvertimePeriod = object.get("data").getAsJsonObject().get("webPortalOvertimePeriod").getAsInt();
                    final String IPv4Addr = object.get("data").getAsJsonObject().get("ip").getAsString();

                    System.out.println("IPv4 Address=" + IPv4Addr);
                    System.out.println("Session ID=" + sessionID);
                    if (portalAuth == false) { // 101 1103 1612 portalAuth == 0
                        message = "恭喜您，已成功登录";
                        retVal = true;
                    }
                    else {
                        while (true) {
                            String portalAuthResult = syncPortalAuthResult(IPv4Addr, sessionID);
                            System.out.println(portalAuthResult);
                            if (portalAuthResult == "") {
                                message = "服务器连接中断，请重新登录";
                                break;
                            }
                            JsonParser parser2=new JsonParser();  //创建JSON解析器
                            JsonObject object2=(JsonObject) parser2.parse(portalAuthResult);  //创建JsonObject对象
                            String message2 = object2.get("message").getAsString();
                            if (message2 == "EmptySessionId") {
                                message = "服务器连接中断，请重新登录";
                                break;
                            }
                            try {
                                dataStr = object2.get("data").getAsString();
                            } catch (Exception e) { // Session timeout
//                                e.printStackTrace();
                                message = "会话已超时";
                                break;
                            }
                            if (dataStr == ""){
                                Integer portalAuthStatus = object2.get("data").getAsJsonObject().get("portalAuthStatus").getAsInt();
                                if (portalAuthStatus == 1) {
                                    // Success
                                    message = "恭喜您，已成功登录";
                                    retVal = true;
                                    break;
                                } else if (portalAuthStatus == 0) {
                                    Thread.sleep(webPortalOvertimePeriod);
                                } else {
                                    Integer portalErrorCode = object2.get("data").getAsJsonObject().get("portalErrorCode").getAsInt();
                                    if (portalErrorCode == 5)
                                        message = "认证失败：当前用户数量已达网络允许的上限，请稍后再试！";
                                    else if (portalErrorCode == 101) // passcode error???
                                        message = "帐号或密码错误";
                                    else if (portalErrorCode > 8000)
                                        message = "第三方radius中继认证失败，请联系管理员处理，第三方错误码：" + (portalErrorCode-8000);
                                    else if (portalErrorCode == 8000)
                                        message = "第三方radius中继认证失败，请联系管理员处理，第三方错误码：未知错误";
                                    else
                                        message = "认证失败";
                                    break;
                                }
                            }

                        }
                    }
                }

                final String messageToDisplay = message;
                final Boolean retVal_ = retVal;
                // 通过runOnUiThread方法进行修改主线程的控件内容
                LoginActivity.this.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        // 在这里把返回的数据写在控件上 会出现什么情况尼
//                        tv_result.setText(result);
                        if (messageToDisplay != "")
                            ShowMsg(messageToDisplay, LoginActivity.this, retVal_);
                        else
                            ShowMsg("未知错误", LoginActivity.this);
                    }
                });
                System.out.println(messageToDisplay);
            } else {
                ShowMsg("Access Failed", LoginActivity.this);
            }
        } catch (Exception e) {
//            e.printStackTrace();
        }
        return retVal;
    }

    public String syncPortalAuthResult(String IPv4Addr, String SessionID) {
        String result = "";
        try {
            // 请求的地址
            String spec = "https://controller1.net.shanghaitech.edu.cn:8445/PortalServer/Webauth/syncPortalAuthResult!login.action";
            // 根据地址创建URL对象
            URL url = new URL(spec);
            // 根据URL对象打开链接
            HttpURLConnection urlConnection = (HttpURLConnection) url
                    .openConnection();
            // 设置请求的方式
            urlConnection.setRequestMethod("POST");
            // 设置请求的超时时间
            urlConnection.setReadTimeout(5000);
            urlConnection.setConnectTimeout(5000);
            // 传递的数据
            String data = "clientIp=" + URLEncoder.encode(IPv4Addr, "UTF-8")
                    + "&browserFlag=" + "zh"
                    ;
            // 设置请求的头
            urlConnection.setRequestProperty("Accept", "*/*");
            // 设置请求的头
            urlConnection.setRequestProperty("Content-Type",
                    "application/x-www-form-urlencoded");
            // 设置请求的头
            urlConnection.setRequestProperty("Cookie",
                    "JSESSIONID=" + SessionID);
            // 设置请求的头
            urlConnection
                    .setRequestProperty("User-Agent",
                            "ShanghaiTech_WIFI_Helper Android");

            urlConnection.setDoOutput(true); // 发送POST请求必须设置允许输出
            urlConnection.setDoInput(true); // 发送POST请求必须设置允许输入
            //setDoInput的默认值就是true
            //获取输出流
            OutputStream os = urlConnection.getOutputStream();
            os.write(data.getBytes());
            os.flush();
            if (urlConnection.getResponseCode() == 200) {
                // 获取响应的输入流对象
                InputStream is = urlConnection.getInputStream();
                // 创建字节输出流对象
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                // 定义读取的长度
                int len = 0;
                // 定义缓冲区
                byte buffer[] = new byte[1024];
                // 按照缓冲区的大小，循环读取
                while ((len = is.read(buffer)) != -1) {
                    // 根据读取的长度写入到os对象中
                    baos.write(buffer, 0, len);
                }
                // 释放资源
                is.close();
                baos.close();
                // 返回字符串
                result = new String(baos.toByteArray());
            } else {
                System.out.println("链接失败.........");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }


    public void ShowMsg(String msg, Context context) {
        ShowMsg(msg, context, false);
    }
    //提示信息
    public void ShowMsg(String msg, Context context, final Boolean finishAfterClick) { //MainActivity.this
        AlertDialog.Builder dlg = new AlertDialog.Builder(context);
        dlg.setTitle(this.getResources().getString(R.string.prompt_info));
        dlg.setMessage(msg);
        dlg.setPositiveButton(this.getResources().getString(R.string.prompt_ok), new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                if (finishAfterClick)
                    finish();
            }
        });
        dlg.show();
    }

    //提示信息
    public void ShowMsgTurnOnWifi(Context context, final WifiManager wifiManager) { //MainActivity.this
        final Context context_ = context;
        final WifiManager wifiManager_ = wifiManager;
        AlertDialog.Builder dlg = new AlertDialog.Builder(context);
        dlg.setTitle(this.getResources().getString(R.string.prompt_info));
        dlg.setMessage(this.getResources().getString(R.string.message_wifi_disabled));
        dlg.setPositiveButton(this.getResources().getString(R.string.prompt_turn_on_wifi), new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                if (wifiManager_ != null) {
                    wifiManager_.setWifiEnabled(true);
                } else {
                    System.err.println("WifiManager is null!");
                }
            }
        });
        dlg.setNegativeButton(this.getResources().getString(R.string.prompt_cancel), null);
        dlg.show();
    }

    //闪现提示
    public static void DisplayToast(String msg, Context context) { //getBaseContext()
        Toast.makeText(context, msg, Toast.LENGTH_SHORT).show();
    }

    public void saveConfig() {
        // Save configurations
        SharedPreferences preferences = getSharedPreferences("ShanghaitechWifiHelper-config",Context.MODE_PRIVATE);
        String username = mUsernameView.getText().toString();
        String password = mPasswordView.getText().toString();
        Boolean isRemember = mRememberView.isChecked();
        Boolean isAutoLogin = mAutoLoginView.isChecked();
        Editor edt = preferences.edit();
        if (mRememberView.isChecked()) {
            edt.putString("username", username);
            edt.putString("password", password);
            edt.putBoolean("isRemember", isRemember);
            edt.putBoolean("isAutoLogin", isAutoLogin);
        } else {
            edt.putString("username", "");
            edt.putString("password", "");
            edt.putBoolean("isRemember", false);
            edt.putBoolean("isAutoLogin", false);
        }
        edt.commit();
    }
}