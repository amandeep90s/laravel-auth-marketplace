<?php

namespace App\Http\Middleware;

use App\Models\Admin;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Auth;

class AdminRedisTokenAuth
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->cookie('admin_auth_token');

        if (!$token) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        // Search for token in Redis across all users
        $admin = Admin::all()->first(function ($u) use ($token) {
            return Cache::get("admin:token:{$u->id}") === $token;
        });

        if (!$admin) {
            return response()->json(['message' => 'Invalid token'], 401);
        }

        // Set the user using the guard instance
        Auth::guard('admin')->setUser($admin);

        return $next($request);
    }
}
