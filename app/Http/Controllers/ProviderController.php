<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Provider;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Cookie;
use Laravel\Sanctum\PersonalAccessToken;

class ProviderController extends Controller
{
    public function login(Request $request)
    {
        $request->validate(['email' => 'required', 'password' => 'required']);

        $provider = Provider::where('email', $request->email)->first();

        if (!$provider || !Hash::check($request->password, $provider->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        $token = $provider->createToken('provider-token', ['*'], now()->addHours(2))->plainTextToken;

        Cache::put("provider:token:{$provider->id}", $token, now()->addHours(2));

        // Set secure=true only for production
        $secure = App::environment('production');

        // Create the cookie
        $cookie = cookie(
            'provider_auth_token',// Cookie name
            $token,           // Value
            120,            // Expiration in minutes
            '/',               // Path
            null,            // Domain (null = current)
            $secure,         // Secure (only HTTPS in prod)
            true,          // HttpOnly
            false,              // Raw
            'Strict'       // SameSite: "Lax" | "Strict" | "None"
        );

        return response()->json([
            'message' => 'Login successful',
            'provider' => $provider
        ])->cookie($cookie);
    }

    public function logout(Request $request)
    {
        // Get token from cookie
        $token = $request->cookie('provider_auth_token');

        if (!$token) {
            return response()->json(['message' => 'No token found'], 400);
        }

        // Find matching token in database
        $accessToken = PersonalAccessToken::findToken($token);

        if (!$accessToken) {
            return response()->json(['message' => 'Invalid token'], 401)->withCookie(Cookie::forget('provider_auth_token'));
        }

        $provider = $accessToken->tokenable;

        // Delete Redis token cache
        Cache::forget("provider:token:{$provider->id}");

        // Revoke the Sanctum token
        $request->user()->tokens()->delete();

        // Remove the HTTP-only cookie
        return response()->json(['message' => 'Logged out successfully'])
            ->withCookie(Cookie::forget('provider_auth_token'));
    }
}
