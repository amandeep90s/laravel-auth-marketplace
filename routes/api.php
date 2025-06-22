<?php

use App\Http\Controllers\AdminController;
use App\Http\Controllers\ProviderController;
use App\Http\Controllers\UserController;
use App\Http\Middleware\AdminRedisTokenAuth;
use App\Http\Middleware\ProviderRedisTokenAuth;
use App\Http\Middleware\UserRedisTokenAuth;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::prefix('auth')->group(function () {
    // Authentication routes for admin
    Route::prefix('admin')->group(function () {
        Route::post('login', [AdminController::class, 'login']);

        Route::middleware([AdminRedisTokenAuth::class])->group(function () {
            Route::post('logout', [AdminController::class, 'logout']);
        });
    });
    // Authentication routes for provider
    Route::prefix('provider')->group(function () {
        Route::post('login', [ProviderController::class, 'login']);

        Route::middleware([ProviderRedisTokenAuth::class])->group(function () {
            Route::post('logout', [ProviderController::class, 'logout']);
        });
    });
    // Authentication routes for user
    Route::prefix('user')->group(function () {
        Route::post('login', [UserController::class, 'login']);

        Route::middleware([UserRedisTokenAuth::class])->group(function () {
            Route::post('logout', [UserController::class, 'logout']);
        });
    });
});


Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');
