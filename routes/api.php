<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Models\User;
use Laravel\Sanctum\Http\Controllers\CsrfCookieController;

// Route for CSRF token setup
Route::get('sanctum/csrf-cookie', [CsrfCookieController::class, 'show']);

// Authentication routes
Route::post('/login', [AuthController::class, 'login']);
Route::post('/logout', [AuthController::class, 'logout'])->middleware('auth:sanctum');

// Protected routes
Route::middleware('auth:sanctum')->group(function () {
    Route::get('/users', function () {
        return User::paginate(10);
    });
});
