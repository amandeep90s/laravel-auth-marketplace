<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Admin;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Cookie;
use Laravel\Sanctum\PersonalAccessToken;

class AdminController extends Controller
{
    public function login(Request $request)
    {
        $request->validate(['email' => 'required', 'password' => 'required']);

        $admin = Admin::where('email', $request->email)->first();

        if (!$admin || !Hash::check($request->password, $admin->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        $token = $admin->createToken('admin-token', ['*'], now()->addHours(2))->plainTextToken;

        // Cache the token in Redis
        Cache::put("admin:token:{$admin->id}", $token, now()->addHours(2));

        // Set secure=true only for production
        $secure = App::environment('production');

        // Create the cookie
        $cookie = cookie(
            'admin_auth_token',// Cookie name
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
            'admin' => $admin
        ])->cookie($cookie);
    }

    public function logout(Request $request)
    {
        // Get token from cookie
        $token = $request->cookie('admin_auth_token');

        if (!$token) {
            return response()->json(['message' => 'No token found'], 400);
        }

        // Find matching token in database
        $accessToken = PersonalAccessToken::findToken($token);

        if (!$accessToken) {
            return response()->json(['message' => 'Invalid token'], 401)->withCookie(Cookie::forget('admin_auth_token'));
        }

        $admin = $accessToken->tokenable;

        // Delete Redis token cache
        Cache::forget("admin:token:{$admin->id}");

        // Revoke the Sanctum token
        $accessToken->delete();

        // Remove the HTTP-only cookie
        return response()->json(['message' => 'Logged out successfully'])
            ->withCookie(Cookie::forget('admin_auth_token'));
    }
}
