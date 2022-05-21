library flutter_appauth_web;

import 'dart:async';
import 'dart:convert';

import 'dart:math';
import 'dart:typed_data';
import 'dart:html' as html;
import 'dart:core';
import 'package:flutter_web_plugins/flutter_web_plugins.dart';
import 'package:http/http.dart' as http;

import 'package:flutter_appauth_platform_interface/flutter_appauth_platform_interface.dart';
import 'package:pointycastle/digests/sha256.dart';

/// A Calculator.
class AppAuthWebPlugin extends FlutterAppAuthPlatform {
  static const String _charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  static const String _DISCOVERY_ERROR_MESSAGE_FORMAT = "Error retrieving discovery document: [error: discovery_failed, description: %2]";
  static const String _TOKEN_ERROR_MESSAGE_FORMAT = "Failed to get token: [error: token_failed, description: %2]";
  static const String _AUTHORIZE_ERROR_MESSAGE_FORMAT = "Failed to authorize: [error: %1, description: %2]";

  static const String _AUTHORIZE_AND_EXCHANGE_CODE_ERROR_CODE = "authorize_and_exchange_code_failed";
  static const String _AUTHORIZE_ERROR_CODE = "authorize_failed";

  static const String _CODE_VERIFIER_STORAGE = "auth_code_verifier";
  static const String _AUTHORIZE_DESTINATION_URL = "auth_destination_url";
  static const String _AUTH_RESPONSE_INFO = "auth_info";

  static registerWith(Registrar registrar) {
    FlutterAppAuthPlatform.instance = AppAuthWebPlugin();
  }

  @override
  Future<AuthorizationTokenResponse?> authorizeAndExchangeCode(AuthorizationTokenRequest request) async {
    final authUrl = html.window.sessionStorage[_AUTHORIZE_DESTINATION_URL];
    if (authUrl != null || authUrl != null && authUrl.isNotEmpty) return null;

    final authResult = await authorize(AuthorizationRequest(request.clientId, request.redirectUrl,
        loginHint: request.loginHint,
        scopes: request.scopes,
        serviceConfiguration: request.serviceConfiguration,
        additionalParameters: request.additionalParameters,
        allowInsecureConnections: request.allowInsecureConnections!,
        discoveryUrl: request.discoveryUrl,
        issuer: request.issuer,
        preferEphemeralSession: request.preferEphemeralSession!,
        promptValues: request.promptValues));

    if (authResult == null) return null;

    final tokenResponse = await requestToken(TokenRequest(request.clientId, request.redirectUrl,
        clientSecret: request.clientSecret,
        serviceConfiguration: request.serviceConfiguration,
        allowInsecureConnections: request.allowInsecureConnections!,
        authorizationCode: authResult.authorizationCode,
        codeVerifier: authResult.codeVerifier,
        discoveryUrl: request.discoveryUrl,
        grantType: "authorization_code",
        issuer: request.issuer));

    return AuthorizationTokenResponse(tokenResponse.accessToken, tokenResponse.refreshToken, tokenResponse.accessTokenExpirationDateTime, tokenResponse.idToken,
        tokenResponse.tokenType, tokenResponse.scopes, authResult.authorizationAdditionalParameters, tokenResponse.tokenAdditionalParameters);
  }

  @override
  Future<AuthorizationResponse?> authorize(AuthorizationRequest request) async {
    String? codeVerifier;

    // check if we already have login-callback data
    final authUrl = html.window.sessionStorage[_AUTH_RESPONSE_INFO];
    if (authUrl != null && authUrl.isNotEmpty) {
      html.window.sessionStorage.remove(_AUTH_RESPONSE_INFO);

      codeVerifier = html.window.sessionStorage[_CODE_VERIFIER_STORAGE];
      if (codeVerifier == null || codeVerifier.isEmpty) return null;
      html.window.sessionStorage.remove(_CODE_VERIFIER_STORAGE);

      return processLoginResult(authUrl, codeVerifier);
    }

    final serviceConfiguration = await getConfiguration(request.serviceConfiguration, request.discoveryUrl, request.issuer);

    request.serviceConfiguration = serviceConfiguration; //Fill in the values from the discovery doc if needed for future calls.
    codeVerifier = List.generate(128, (i) => _charset[Random.secure().nextInt(_charset.length)]).join();

    final codeChallenge = base64Url.encode(SHA256Digest().process(Uint8List.fromList(codeVerifier.codeUnits))).replaceAll('=', '');

    var responseType = "code";

    var authUri =
        "${serviceConfiguration.authorizationEndpoint}?client_id=${request.clientId}&redirect_uri=${Uri.encodeQueryComponent(request.redirectUrl)}&response_type=$responseType&scope=${Uri.encodeQueryComponent(request.scopes!.join(' '))}&code_challenge_method=S256&code_challenge=$codeChallenge";

    if (request.loginHint != null) authUri += "&login_hint=${Uri.encodeQueryComponent(request.loginHint!)}";

    if (request.promptValues != null)
      request.promptValues!.forEach((element) {
        authUri += "&prompt=$element";
      });
    if (request.additionalParameters != null) request.additionalParameters!.forEach((key, value) => authUri += "&$key=$value");

    String loginResult;
    try {
      if (request.promptValues != null && request.promptValues!.contains("none")) {
        //Do this in an iframe instead of a popup because this is a silent renew
        loginResult = await openIframe(authUri, 'auth');
      } else {
        html.window.sessionStorage[_AUTHORIZE_DESTINATION_URL] = html.window.location.href;
        html.window.sessionStorage[_CODE_VERIFIER_STORAGE] = codeVerifier;
        html.window.location.assign(authUri);
        return null;
        // loginResult = await openPopUp(authUri, 'auth', 640, 600, true);
      }
    } on StateError catch (err) {
      throw StateError(_AUTHORIZE_ERROR_MESSAGE_FORMAT.replaceAll("%1", _AUTHORIZE_AND_EXCHANGE_CODE_ERROR_CODE).replaceAll("%2", err.message));
    }

    return processLoginResult(loginResult, codeVerifier);
  }

  @override
  Future<TokenResponse> token(TokenRequest request) {
    return requestToken(request);
  }

  @override
  Future<EndSessionResponse?> endSession(EndSessionRequest request) async {
    final AuthorizationServiceConfiguration serviceConfiguration = await getConfiguration(request.serviceConfiguration, request.discoveryUrl, request.issuer);
    String uri = "${serviceConfiguration.endSessionEndpoint}?id_token_hint=${request.idTokenHint}";

    if (request.idTokenHint != null && request.postLogoutRedirectUrl != null) {
      uri += "&post_logout_redirect_uri=${Uri.encodeQueryComponent(request.postLogoutRedirectUrl!)}";
    }

    if (request.postLogoutRedirectUrl != null && request.state != null) {
      uri += "&state=${request.state}";
    }

    // lets redirect to the endsession uri
    html.window.location.assign(uri);

    return EndSessionResponse(null);
  }

  Future<TokenResponse> requestToken(TokenRequest request) async {
    final serviceConfiguration = await getConfiguration(request.serviceConfiguration, request.discoveryUrl, request.issuer);

    request.serviceConfiguration = serviceConfiguration; //Fill in the values from the discovery doc if needed for future calls

    var body = {"client_id": request.clientId, "grant_type": request.grantType, "redirect_uri": request.redirectUrl};

    if (request.clientSecret != null) body["client_secret"] = request.clientSecret;

    if (request.authorizationCode != null) body["code"] = request.authorizationCode;
    if (request.codeVerifier != null) body["code_verifier"] = request.codeVerifier;
    if (request.refreshToken != null) body["refresh_token"] = request.refreshToken;
    if (request.scopes != null && request.scopes!.isNotEmpty) body["scopes"] = request.scopes!.join(" ");

    if (request.additionalParameters != null) body.addAll(request.additionalParameters!);

    final response = await http.post(Uri.parse(serviceConfiguration.tokenEndpoint), body: body);

    final Map<String, dynamic> jsonResponse = jsonDecode(response.body);

    if (response.statusCode != 200) {
      print(jsonResponse["error"].toString());
      throw ArgumentError(_TOKEN_ERROR_MESSAGE_FORMAT.replaceAll("%2", jsonResponse["error"]?.toString() ?? response.reasonPhrase ?? "Unknown Error"));
    }
    List<String>? scopes =
        jsonResponse["scope"] is String == true ? ((jsonResponse["scope"].split(' ') as List?)?.cast<String>()) : (jsonResponse["scope"] as List?)?.cast<String>();
    return TokenResponse(
      jsonResponse["access_token"].toString(),
      jsonResponse["refresh_token"] == null ? null : jsonResponse["refresh_token"].toString(),
      DateTime.now().add(new Duration(seconds: jsonResponse["expires_in"])),
      jsonResponse["id_token"].toString(),
      jsonResponse["token_type"].toString(),
      scopes,
      jsonResponse,
    );
  }

  //returns null if full login is required
  AuthorizationResponse processLoginResult(String loginResult, String codeVerifier) {
    var resultUri = Uri.parse(loginResult.toString());

    final error = resultUri.queryParameters['error'];

    if (error != null && error.isNotEmpty) throw ArgumentError(_AUTHORIZE_ERROR_MESSAGE_FORMAT.replaceAll("%1", _AUTHORIZE_ERROR_CODE).replaceAll("%2", error));

    var authCode = resultUri.queryParameters['code'];
    if (authCode == null || authCode.isEmpty)
      throw ArgumentError(_AUTHORIZE_ERROR_MESSAGE_FORMAT.replaceAll("%1", _AUTHORIZE_ERROR_CODE).replaceAll("%2", 'Login request returned no code'));

    return AuthorizationResponse(
      authorizationCode: authCode,
      codeVerifier: codeVerifier,
      authorizationAdditionalParameters: resultUri.queryParameters,
    );
  }

  //to-do Cache this based on the url
  Future<AuthorizationServiceConfiguration> getConfiguration(AuthorizationServiceConfiguration? serviceConfiguration, String? discoveryUrl, String? issuer) async {
    if ((discoveryUrl == null || discoveryUrl == '') && (issuer == null || issuer == '') && serviceConfiguration == null)
      throw ArgumentError('You must specify either a discoveryUrl, issuer, or serviceConfiguration');

    if (serviceConfiguration != null) return serviceConfiguration;

    //Handle lookup here.
    if (discoveryUrl == null || discoveryUrl == '') discoveryUrl = "$issuer/.well-known/openid-configuration";

    final response = await http.get(Uri.parse(discoveryUrl));
    if (response.statusCode != 200) throw UnsupportedError(_DISCOVERY_ERROR_MESSAGE_FORMAT.replaceAll("%2", response.reasonPhrase ?? "Unknown Error"));

    final jsonResponse = jsonDecode(response.body);
    return AuthorizationServiceConfiguration(
      authorizationEndpoint: jsonResponse["authorization_endpoint"].toString(),
      tokenEndpoint: jsonResponse["token_endpoint"].toString(),
      endSessionEndpoint: jsonResponse["end_session_endpoint"].toString(),
    );
  }

  Future<String> openPopUp(String url, String name, int width, int height, bool center, {String? additionalOptions}) async {
    var options = 'width=$width,height=$height,toolbar=no,location=no,directories=no,status=no,menubar=no,copyhistory=no';
    if (center) {
      final top = (html.window.outerHeight - height) / 2 + (html.window.screen?.available.top ?? 0);
      final left = (html.window.outerWidth - width) / 2 + (html.window.screen?.available.left ?? 0);

      options += 'top=$top,left=$left';
    }

    if (additionalOptions != null && additionalOptions != '') options += ',$additionalOptions';

    final child = html.window.open(url, name, options);
    final c = new Completer<String>();

    html.window.onMessage.first.then((event) {
      final url = event.data.toString();
      print(url);
      c.complete(url);
      child.close();
    });

    //This handles the user closing the window without a response
    while (!c.isCompleted) {
      await Future.delayed(Duration(milliseconds: 500));
      if ((child.closed ?? false) && !c.isCompleted) c.completeError(StateError('User Closed'));

      if (c.isCompleted) break;
    }

    return c.future;
  }

  Future<String> openIframe(String url, String name) async {
    final child = html.IFrameElement();
    child.name = name;
    child.src = url;
    child.height = '10';
    child.width = '10';
    child.style.border = 'none';
    child.style.display = 'none';

    html.querySelector("body")?.children.add(child);

    final c = new Completer<String>();

    html.window.onMessage.first.then((event) {
      final url = event.data.toString();
      print(url);
      c.complete(url);
      html.querySelector("body")?.children.remove(child);
    });

    return c.future;
  }
}
