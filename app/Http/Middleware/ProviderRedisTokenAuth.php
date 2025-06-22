<?php

namespace App\Http\Middleware;

use App\Models\Provider;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Auth;

class ProviderRedisTokenAuth
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->cookie('provider_auth_token');

        if (!$token) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        // Search for token in Redis across all users
        $provider = Provider::all()->first(function ($u) use ($token) {
            return Cache::get("provider:token:{$u->id}") === $token;
        });

        if (!$provider) {
            return response()->json(['message' => 'Invalid token'], 401);
        }

        // Set the user using the guard instance
        Auth::guard('provider')->setUser($provider);

        return $next($request);
    }
}
