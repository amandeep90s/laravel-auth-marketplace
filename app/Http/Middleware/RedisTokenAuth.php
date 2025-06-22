<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Support\Str;

class RedisTokenAuth
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $authHeader = $request->header('Authorization');

        if (!$authHeader || !Str::startsWith($authHeader, 'Bearer ')) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        $token = Str::replaceFirst('Bearer ', '', $authHeader);

        // Search for token in Redis across all users
        $user = User::all()->first(function ($u) use ($token) {
            return Cache::get("user:token:{$u->id}") === $token;
        });

        if (!$user) {
            return response()->json(['message' => 'Invalid token'], 401);
        }

        // Set the user using the guard instance
        Auth::guard('user')->setUser($user);

        return $next($request);
    }
}
