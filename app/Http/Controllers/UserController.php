<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Validation\ValidationException;
use Laravel\Sanctum\PersonalAccessToken;

class UserController extends Controller
{
    public function login(Request $request)
    {
        $request->validate(['email' => 'required', 'password' => 'required']);

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        if (!Hash::check($request->password, (string) $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $token = $user->createToken('user-token', ['*'], now()->addHours(2))->plainTextToken;

        Cache::put("user:token:{$user->id}", $token, now()->addHours(2));

        // Set secure=true only for production
        $secure = App::environment('production');

        // Create the cookie
        $cookie = cookie(
            'user_auth_token', // Cookie name
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
            'user' => $user
        ])->cookie($cookie);
    }

    public function logout(Request $request)
    {
        // Get token from cookie
        $token = $request->cookie('user_auth_token');

        if (!$token) {
            return response()->json(['message' => 'No token found'], 400);
        }

        // Find matching token in database
        $accessToken = PersonalAccessToken::findToken($token);

        if (!$accessToken) {
            return response()->json(['message' => 'Invalid token'], 401)->withCookie(Cookie::forget('user_auth_token'));
        }

        $user = $accessToken->tokenable;

        // Delete Redis token cache
        Cache::forget("user:token:{$user->id}");

        // Revoke the Sanctum token
        $request->user()->tokens()->delete();

        // Remove the HTTP-only cookie
        return response()->json(['message' => 'Logged out successfully'])
            ->withCookie(Cookie::forget('user_auth_token'));
    }
}
