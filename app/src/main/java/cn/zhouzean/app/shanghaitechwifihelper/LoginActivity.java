package cn.zhouzean.app.shanghaitechwifihelper;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.annotation.TargetApi;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Looper;
import android.support.annotation.NonNull;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.app.LoaderManager.LoaderCallbacks;

import android.content.CursorLoader;
import android.content.Loader;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.view.Gravity;

import android.os.Build;
import android.os.Bundle;
import android.provider.ContactsContract;
import android.support.v7.widget.Toolbar;
import android.text.SpannableString;
import android.text.TextUtils;
import android.text.util.Linkify;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
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

import android.text.method.LinkMovementMethod;

import java.util.ArrayList;
import java.util.List;
import java.lang.reflect.Field;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Random;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import android.util.Base64;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.net.ConnectivityManager;
import android.net.NetworkRequest;
import android.net.NetworkCapabilities;
import android.net.Network;
import android.content.Context;
import android.content.Intent;
import android.os.Process;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonIOException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;

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
		Toolbar mToolbar = (Toolbar) findViewById(R.id.toolbar1);
		setSupportActionBar(mToolbar);

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
		else
			DisplayToast(getString(R.string.message_widget_need_auto_connect), LoginActivity.this);


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
					if (SSID.startsWith("\"") && SSID.endsWith("\""))
						SSID = SSID.substring(1, SSID.length()-1);
					if (!SSID.equals("ShanghaiTech") && !SSID.equals("guest")) {
						ShowMsgNotShanghaiTech(this.getResources().getString(R.string.message_wifi_wrong_ssid)+"\nSSID: "+SSID, LoginActivity.this);
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
			if (success) {
				System.out.println("SUCCESS");
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
		String sessionID;
		String XSRF_TOKEN;
		try {
			// 请求的地址
			String spec = "https://controller.shanghaitech.edu.cn:8445/PortalServer/Webauth/webAuthAction!login.action";
			// 根据地址创建URL对象
			URL url = new URL(spec);
			// 根据URL对象打开链接
			HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
			// 设置请求的方式
			urlConnection.setRequestMethod("POST");
			// 设置请求的超时时间
			urlConnection.setReadTimeout(2000);
			urlConnection.setConnectTimeout(2000);
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
					"JSESSIONID=" + getRandomString(32));
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

				Boolean success = object.get("success").getAsBoolean();
				String message = object.get("message").getAsString();
//                System.out.println("message="+message);
//                System.out.println("success="+success);

				String dataStr = "";
				try {
					dataStr = object.get("data").getAsString();
				} catch (Exception e) { // cannot be parsed as string... JSON Obj
//                    e.printStackTrace();
				}
//                System.out.println("dataStr = " + dataStr);

				if (!message.equals("") && message.indexOf("token") < 0) {
					// failed
				}
				else if (dataStr.equals("session_timeout") || object.get("sessionTimeOut").getAsBoolean()) {
					message = "会话已超时";
				}
				else { // if (success)
					sessionID = object.get("data").getAsJsonObject().get("sessionId").getAsString();
					XSRF_TOKEN = object.get("token").getAsString().substring(6);
					Boolean portalAuth = object.get("data").getAsJsonObject().get("portalAuth").getAsBoolean();
					Integer webPortalOvertimePeriod = object.get("data").getAsJsonObject().get("webPortalOvertimePeriod").getAsInt();
					final String IPv4Addr = object.get("data").getAsJsonObject().get("ip").getAsString();

					System.out.println("IPv4 Address=" + IPv4Addr);
					System.out.println("Session ID=" + sessionID);
					System.out.println("XSRF_TOKEN=" + XSRF_TOKEN);
					if (portalAuth == false) { // 101 1103 1612 portalAuth == 0
						message = "恭喜您，已成功登录";
						retVal = true;
					}
					else {
						Integer postCount;
						for (postCount = 0; postCount < 10; postCount++) {
							String portalAuthResult = syncPortalAuthResult(IPv4Addr, sessionID, XSRF_TOKEN);
							portalAuthResult = portalAuthResult.replace("null", "\"\""); // Avoid null
							System.out.println(portalAuthResult);
							if (portalAuthResult.equals("")) {
								message = getString(R.string.message_httpcode_not_200);
								break;
							}
							JsonParser parser2=new JsonParser();  //创建JSON解析器
							JsonObject object2=(JsonObject) parser2.parse(portalAuthResult);  //创建JsonObject对象
							String message2 = object2.get("message").getAsString();

							if (message2.equals("EmptySessionId")) {
								message = "服务器连接中断，请重新登录";
								break;
							}
							try {
								dataStr = object2.get("data").getAsString();
							} catch (Exception e) { // Session timeout
//                                e.printStackTrace();
							}
							if (dataStr.equals("")){
								Integer portalAuthStatus = object2.get("data").getAsJsonObject().get("portalAuthStatus").getAsInt();
								if (portalAuthStatus == 1) {
									// Success
									message = "恭喜您，已成功登录";
									retVal = true;
									break;
								} else if (portalAuthStatus == 0) {
//                                    Looper.prepare();
//                                    DisplayToast(getString(R.string.message_post_again)+" ("+(repostCount)+")", LoginActivity.this);
//                                    Looper.loop();
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
										message = "认证失败 ("+portalErrorCode.toString()+")";
									break;
								}
							} else {
								message = message2;
								break; // dataStr has content
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
//                        tv_result.setText(result);
						if (!messageToDisplay.equals(""))
							ShowMsg(messageToDisplay, LoginActivity.this, retVal_);
						else
							ShowMsg("未知错误", LoginActivity.this);
					}
				});
				System.out.println(messageToDisplay);
			} else {
				ShowMsg(getString(R.string.message_httpcode_not_200) + "(100)", LoginActivity.this);
			}
		}
        catch (java.net.UnknownHostException | java.net.SocketTimeoutException e) {
            LoginActivity.this.runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    ShowMsg(getString(R.string.message_httpcode_not_200) + "(102)", LoginActivity.this);
                }
            });
        }
		catch (final Exception e) {
			final String msg = exceptionToString(e);
			System.out.println(e.toString());
			LoginActivity.this.runOnUiThread(new Runnable() {
				@Override
				public void run() {
					ShowMsg("致命错误，请立刻报告Bug！\n"+e.toString()+"\n"+msg, LoginActivity.this);
				}
			});
		}
		if (retVal && checkUpdateInfo()) { // if auth successfully && interval > 3 days, check new version
			doUpgrade(false);
        }
		return retVal;
	}

	public String syncPortalAuthResult(String IPv4Addr, String SessionID, String XSRF_TOKEN) {
		String result = "";
		try {
			// 请求的地址
			String spec = "https://controller.shanghaitech.edu.cn:8445/PortalServer/Webauth/webAuthAction!syncPortalAuthResult.action";
			// 根据地址创建URL对象
			URL url = new URL(spec);
			// 根据URL对象打开链接
			HttpURLConnection urlConnection = (HttpURLConnection) url
					.openConnection();
			// 设置请求的方式
			urlConnection.setRequestMethod("POST");
			// 设置请求的超时时间
			urlConnection.setReadTimeout(2000);
			urlConnection.setConnectTimeout(2000);
			// 传递的数据
			String data = "clientIp=" + URLEncoder.encode(IPv4Addr, "UTF-8")
					+ "&browserFlag=" + "zh"
					;
			System.out.println("POST Request: " + data);
			// 设置请求的头
			urlConnection.setRequestProperty("Accept", "*/*");
			urlConnection.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4");
			urlConnection.setRequestProperty("Accept-Encoding", "gzip, deflate, br");
			urlConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
			urlConnection.setRequestProperty("X-Requested-With", "XMLHttpRequest");
			urlConnection.setRequestProperty("X-XSRF-TOKEN", XSRF_TOKEN);
			urlConnection.setRequestProperty("Cookie", "JSESSIONID=" + SessionID + "; " + "XSRF_TOKEN=" + XSRF_TOKEN);
			urlConnection.setRequestProperty("User-Agent", "ShanghaiTech_WIFI_Helper Android");

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
				System.out.println("Sync Connection Failed...");
			}
		}
        catch (java.net.UnknownHostException | java.net.SocketTimeoutException e) {
            LoginActivity.this.runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    ShowMsg(getString(R.string.message_httpcode_not_200) + "(102.1)", LoginActivity.this);
                }
            });
        }
		catch (final Exception e) {
			final String msg = exceptionToString(e);
			System.out.println(e.toString());
			LoginActivity.this.runOnUiThread(new Runnable() {
				@Override
				public void run() {
					ShowMsg("致命错误，请立刻报告Bug！\n"+e.toString()+"\n"+msg, LoginActivity.this);
				}
			});
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
    public void ShowMsgNotShanghaiTech(String msg, Context context) { //MainActivity.this
        AlertDialog.Builder dlg = new AlertDialog.Builder(context);
        dlg.setTitle(this.getResources().getString(R.string.prompt_info));
        dlg.setMessage(msg);
        dlg.setPositiveButton(this.getResources().getString(R.string.prompt_ok), null);
        dlg.setNegativeButton(this.getResources().getString(R.string.prompt_ignore), new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                String username = mUsernameView.getText().toString();
                String password = mPasswordView.getText().toString();
                showProgress(true);
                mAuthTask = new UserLoginTask(username, password);
                mAuthTask.execute((Void) null);
            }
        });
        dlg.show();
    }

	//提示信息
	public void ShowMsgTurnOnWifi(Context context, final WifiManager wifiManager) { //MainActivity.this
		AlertDialog.Builder dlg = new AlertDialog.Builder(context);
		dlg.setTitle(this.getResources().getString(R.string.prompt_info));
		dlg.setMessage(this.getResources().getString(R.string.message_wifi_disabled));
		dlg.setPositiveButton(this.getResources().getString(R.string.prompt_turn_on_wifi), new DialogInterface.OnClickListener() {
			@Override
			public void onClick(DialogInterface dialog, int which) {
				if (wifiManager != null) {
					wifiManager.setWifiEnabled(true);
				} else {
					System.err.println("WifiManager is null!");
				}
			}
		});
		dlg.setNegativeButton(this.getResources().getString(R.string.prompt_cancel), null);
		dlg.show();
	}
    //提示信息
    public void ShowMsgUpdate(Context context, final String url, String versionName, String newFeatures) { //MainActivity.this
        AlertDialog.Builder dlg = new AlertDialog.Builder(context);
        dlg.setTitle(this.getResources().getString(R.string.prompt_info));
        dlg.setMessage(this.getResources().getString(R.string.message_new_version)+" ("+versionName+")"+"\n\n"+newFeatures);
        dlg.setPositiveButton(this.getResources().getString(R.string.prompt_update), new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                Intent i = new Intent(Intent.ACTION_VIEW);
                i.setData(Uri.parse(url)); // invoke default downloader
                startActivity(i);
            }
        });
        dlg.setNegativeButton(this.getResources().getString(R.string.prompt_cancel), null);
        dlg.show();
    }
	public void ShowMsgAbout(Context context, String text) {
//        final TextView message = new TextView(context);
        final SpannableString s = new SpannableString(text);
        Linkify.addLinks(s, Linkify.WEB_URLS);
//        message.setText(s);
//        message.setMovementMethod(LinkMovementMethod.getInstance());

        AlertDialog dlg = new AlertDialog.Builder(LoginActivity.this)
        .setTitle(this.getResources().getString(R.string.menu_about))
		.setMessage(s)
		.setPositiveButton(this.getResources().getString(R.string.prompt_ok), null)
		.show();

        TextView alertTextView = (TextView) dlg.findViewById(android.R.id.message);
        alertTextView.setMovementMethod(LinkMovementMethod.getInstance());
        alertTextView.setGravity(Gravity.CENTER_HORIZONTAL);
	}

	//闪现提示
	public void DisplayToast(String msg, Context context) { //getBaseContext()
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

	public Boolean checkUpdateInfo() {
		SharedPreferences preferences = getSharedPreferences("ShanghaitechWifiHelper-updateinfo",Context.MODE_PRIVATE);
		long lastUpdateTime = preferences.getLong("lastUpdateTime", 0);
		System.out.println("lastUpdateTime="+lastUpdateTime);
		if ((System.currentTimeMillis() - lastUpdateTime)/1000/60/60/24 < 3) // update interval = 3 days
			return false;
		Editor edt = preferences.edit();
		edt.putLong("lastUpdateTime", System.currentTimeMillis());
		edt.commit();
		return true;
	}
	public Boolean isVersionOutdated(String oldVersionName, String newVersionName) {
		String[] oldVersion = oldVersionName.split("\\.");
		String[] newVersion = newVersionName.split("\\.");
		for (Integer i = 0; i < 3; ++i) {
            if (Integer.parseInt(oldVersion[i]) < Integer.parseInt(newVersion[i]))
			 	return true;
            else if (Integer.parseInt(oldVersion[i]) > Integer.parseInt(newVersion[i]))
                return false;
		}
		return false;
	}
	public String exceptionToString(Exception e) {
		StringBuffer sb = new StringBuffer();
		StackTraceElement[] stackArray = e.getStackTrace();
		for (int i = 0; i < stackArray.length; i++) {
			StackTraceElement element = stackArray[i];
			sb.append(element.toString() + "\n");
		}
		System.out.println("<DEBUG: "+sb.toString()+">");
		SharedPreferences preferences = getSharedPreferences("ShanghaitechWifiHelper-debug",Context.MODE_PRIVATE);
		Editor edt = preferences.edit();
		edt.putString("detail", sb.toString());
		edt.putLong("time", System.currentTimeMillis());
		edt.commit();
		return sb.toString();
	}

	public void doUpgrade(final Boolean alwaysShowDiag) {
		try {
            String spec_auth = "http://app.zhouzean.cn/wifihelper/";
            URL url_auth = new URL(spec_auth);
            HttpURLConnection urlConnection_auth = (HttpURLConnection) url_auth.openConnection();
            urlConnection_auth.setReadTimeout(2000);
            urlConnection_auth.setConnectTimeout(2000);
            InputStream is = urlConnection_auth.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            String result = "";
            String buffer;
            while ((buffer = reader.readLine()) != null)
                result += buffer;
            System.out.println("NEW VERSION INFO: " + result);

            JsonParser parser = new JsonParser();  //创建JSON解析器
            JsonObject object = (JsonObject) parser.parse(result);  //创建JsonObject对象

            final String nowVersionName = this.getPackageManager().getPackageInfo(this.getPackageName(), 0).versionName;
            final String newVersionName = object.get("versionName").getAsString();
            final String url = object.get("url").getAsString();

            StringBuffer sb = new StringBuffer();
            JsonArray list = object.get("info").getAsJsonArray();
            for (JsonElement s: list) {
                sb.append(s.getAsString());
                sb.append("\n");
            }
            if (sb.length() >= 1)
                sb.deleteCharAt(sb.length()-1); // Delete Extra newline
            final String newFeatures = new String(sb);
            System.out.println(newFeatures);

            if (isVersionOutdated(nowVersionName, newVersionName)) // if outdated, ask for updating
                LoginActivity.this.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        ShowMsgUpdate(LoginActivity.this, url, newVersionName, newFeatures);
                    }
                });
            else if (alwaysShowDiag)
                LoginActivity.this.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        ShowMsg(getString(R.string.message_already_latest), LoginActivity.this);
                    }
                });
        } catch (java.io.IOException e) {
            LoginActivity.this.runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    if (alwaysShowDiag)
                        ShowMsg(getString(R.string.message_update_failure), LoginActivity.this);
                }
            });
		} catch (final Exception e) {
			final String msg = exceptionToString(e);
			System.out.println(e.toString());
			LoginActivity.this.runOnUiThread(new Runnable() {
				@Override
				public void run() {
					ShowMsg("致命错误，请立刻报告Bug！\n"+e.toString()+"\n"+msg, LoginActivity.this);
				}
			});
		}
	}

//    private void bindToNetwork() {
//        final ConnectivityManager connectivityManager = (ConnectivityManager) LoginActivity.getSystemService(Context.CONNECTIVITY_SERVICE);
//            NetworkRequest.Builder builder;
//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
//            builder = new NetworkRequest.Builder();
//            //set the transport type to WIFI
//            builder.addTransportType(NetworkCapabilities.TRANSPORT_WIFI);
//            connectivityManager.requestNetwork(builder.build(), new ConnectivityManager.NetworkCallback() {
//                @Override
//                public void onAvailable(Network network) {
//                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
//                        connectivityManager.bindProcessToNetwork(null);
//                        if (barCodeData.getSsid().contains("screenspace")) {
//                            connectivityManager.bindProcessToNetwork(network);
//                        }
//
//                    } else {
//                        //This method was deprecated in API level 23
//                        ConnectivityManager.setProcessDefaultNetwork(null);
//                        if (barCodeData.getSsid().contains("screenspace")) {
//                            ConnectivityManager.setProcessDefaultNetwork(network);
//                        }
//                    }
//                    connectivityManager.unregisterNetworkCallback(this);
//                }
//            });
//        }
//    }
	private Lock BugReportLock = new ReentrantLock();
	private boolean isCancelled = false;
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
			case R.id.action_update:
                DisplayToast(getString(R.string.message_checking_update), LoginActivity.this);
                Thread thread_update = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try  {
                            doUpgrade(true);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                });

                thread_update.setPriority(Process.THREAD_PRIORITY_BACKGROUND);
                thread_update.start();
				return true;

			case R.id.action_bugreport:
				isCancelled = false;
                View view = getLayoutInflater().inflate(R.layout.bug_report,null);
                final EditText et_name = (EditText) view.findViewById(R.id.name);
                final EditText et_contact = (EditText) view.findViewById(R.id.contact);
                final EditText et_feedback = (EditText) view.findViewById(R.id.feedback);
                final AlertDialog dlg = new AlertDialog.Builder(LoginActivity.this)
                .setView(view)
                .setTitle(getString(R.string.menu_bugreport))
                .setPositiveButton(this.getResources().getString(R.string.prompt_ok), new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(final DialogInterface dialog, int which) {
						View focusView = null;
                        final String name = et_name.getText().toString();
                        final String contact = et_contact.getText().toString();
                        final String feedback = et_feedback.getText().toString();
                        try {
                            Field field = dialog.getClass().getSuperclass().getDeclaredField("mShowing");
                            field.setAccessible(true);
                            field.set(dialog, false); // 设置AlertDialog不可被Button关闭
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        if (TextUtils.isEmpty(name)) {
                            et_name.setError(getString(R.string.error_field_required));
                            if (focusView == null)
                                focusView = et_name;
                        }
                        if (TextUtils.isEmpty(feedback)) {
                            et_feedback.setError(getString(R.string.error_field_required));
                            if (focusView == null)
                                focusView = et_feedback;
                        }
                        if (focusView != null) {
                            focusView.requestFocus();
                            return;
                        }

                        // 设置EditText不可修改
                        et_name.setKeyListener(null);
                        et_contact.setKeyListener(null);
                        et_feedback.setKeyListener(null);

                        Thread thread_bugreport = new Thread(new Runnable() {
                            @Override
                            public void run() {
								if (!BugReportLock.tryLock())
									return;
								LoginActivity.this.runOnUiThread(new Runnable() {
									@Override
									public void run() {
										DisplayToast(getString(R.string.message_feedback_sending_now), LoginActivity.this);
									}
								});
                                try {
                                    String ip = "127.0.0.1";
                                    WifiManager wifiManager = (WifiManager) LoginActivity.this.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                                    if (wifiManager.isWifiEnabled()) {
                                        WifiInfo wifiInfo = wifiManager.getConnectionInfo();
                                        int ipAddress = wifiInfo.getIpAddress();
                                        ip = (ipAddress & 0xFF) + "." +
                                                ((ipAddress >> 8) & 0xFF) + "." +
                                                ((ipAddress >> 16) & 0xFF) + "." +
                                                (ipAddress >> 24 & 0xFF);
                                    }

                                    Map<String, Object> map = new HashMap<>();
                                    map.put("Name", name);
                                    map.put("Contact", contact);
                                    map.put("Feedback", feedback);
                                    map.put("IP", ip);
                                    map.put("Time", Long.toString(System.currentTimeMillis()));

                                    Gson gson = new GsonBuilder().create();
                                    final String json_string = gson.toJson(map);

                                    System.out.println(json_string);

                                    String spec = "http://api.zhouzean.cn/wifihelper/action.php";
                                    URL url = new URL(spec);
                                    HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
                                    urlConnection.setRequestMethod("POST");
                                    urlConnection.setReadTimeout(3500);
                                    urlConnection.setConnectTimeout(3500);
                                    String data = "data=" + Base64.encodeToString(json_string.getBytes(), Base64.URL_SAFE);

                                    urlConnection.setRequestProperty("Accept", "*/*");
                                    urlConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                                    urlConnection.setRequestProperty("User-Agent", "ShanghaiTech_WIFI_Helper Android");
                                    urlConnection.setDoOutput(true);
                                    urlConnection.setDoInput(true);

									if (isCancelled)
										return;

                                    OutputStream os = urlConnection.getOutputStream();
                                    os.write(data.getBytes());
                                    os.flush();

                                    if (urlConnection.getResponseCode() == 200) {
                                        InputStream is = urlConnection.getInputStream();
                                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                                        int len;
                                        byte buffer[] = new byte[1024];
                                        while ((len = is.read(buffer)) != -1) {
                                            baos.write(buffer, 0, len);
                                        }
                                        is.close();
                                        baos.close();
                                        final String result = new String(baos.toByteArray());

                                        JsonParser parser = new JsonParser();  //创建JSON解析器
                                        JsonObject object = (JsonObject) parser.parse(result);  //创建JsonObject对象

                                        final Boolean isSuccess = object.get("result").getAsBoolean();
                                        if (isSuccess) {
                                            try {
                                                Field field = dialog.getClass().getSuperclass().getDeclaredField("mShowing");
                                                field.setAccessible(true);
                                                field.set(dialog, true);
                                            } catch (Exception e) {
                                                e.printStackTrace();
                                            }
                                            dialog.dismiss();
                                        }
										if (!isCancelled)
											LoginActivity.this.runOnUiThread(new Runnable() {
												@Override
												public void run() {
													if (isSuccess) {
														ShowMsg(getString(R.string.message_feedback_success), LoginActivity.this);
													} else {
														ShowMsg(getString(R.string.message_feedback_failure)+" (201)", LoginActivity.this);
													}
												}
											});

                                    } else {
										if (!isCancelled)
											LoginActivity.this.runOnUiThread(new Runnable() {
												@Override
												public void run() {
													ShowMsg(getString(R.string.message_feedback_failure)+" (200)", LoginActivity.this);
												}
											});
                                    }

                                }
                                catch (java.net.UnknownHostException | java.net.SocketTimeoutException e) {
									if (!isCancelled)
										LoginActivity.this.runOnUiThread(new Runnable() {
											@Override
											public void run() {
												ShowMsg(getString(R.string.message_feedback_failure)+" (202)", LoginActivity.this);
											}
										});
                                }
                                catch (final Exception e) {
                                    final String msg = exceptionToString(e);
                                    System.out.println(e.toString());
                                    LoginActivity.this.runOnUiThread(new Runnable() {
                                        @Override
                                        public void run() {
                                            ShowMsg("致命错误，请立刻报告Bug！\n"+e.toString()+"\n"+msg, LoginActivity.this);
                                        }
                                    });
                                }
                                finally {
									BugReportLock.unlock();
								}
							}
                        });
						thread_bugreport.setPriority(Process.THREAD_PRIORITY_BACKGROUND);
						thread_bugreport.start();
                    }
                })
                .setNegativeButton(this.getResources().getString(R.string.prompt_cancel), new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
						isCancelled = true;
                        try {
                            Field field = dialog.getClass().getSuperclass().getDeclaredField("mShowing");
                            field.setAccessible(true);
                            field.set(dialog, true);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                })
                .setCancelable(false)
                .show();

                return true;

			case R.id.action_about:
				try {
					final String appName = getString(R.string.app_name);
					final String versionName = this.getPackageManager().getPackageInfo(this.getPackageName(), 0).versionName;
                    final String author = getString(R.string.app_author);
					final String siteURL = "www.zhouzean.cn";
//					final String githubURL = "https://github.com/zeanzhou/ShanghaitechWifiHelper";

                    final String text = appName + " (" + versionName + ")\n" + author + "\n" + siteURL;
					ShowMsgAbout(LoginActivity.this, text);
				} catch (final Exception e) {
					System.err.println("Error");
				}
				return true;

			default:
				// If we got here, the user's action was not recognized.
				// Invoke the superclass to handle it.
				return super.onOptionsItemSelected(item);
		}
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main_menu, menu);
		return true;
	}
}