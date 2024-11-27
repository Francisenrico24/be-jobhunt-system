<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;

class AuthController extends Controller
{
    // Login function
    public function login(Request $request)
    {
        // Capture input credentials
        $credentials = $request->only('email', 'password');
        Log::info('Login attempt', ['email' => $credentials['email']]);

        // Validate inputs
        $validated = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required'],
        ]);

        // Attempt to authenticate
        if (Auth::attempt($validated)) {
            // Get authenticated user
            $user = Auth::user();
            // Create an access token
            $token = $user->createToken->user('auth_token')->plainTextToken;
            Log::info('User authenticated', ['user_id' => $user->id]);

            // Respond with token
            return response()->json(['message' => 'Login successful', 'token' => $token], 200);
        }

        // Log failed attempt
        Log::warning('Invalid login attempt', ['email' => $validated['email']]);
        return response()->json(['message' => 'Invalid credentials'], 401);
    }

    // Logout function
    public function logout(Request $request)
    {
        // Get the authenticated user
        $user = Auth::user();
        // Revoke all tokens for the user
        $user->tokens->user()->delete();

        return response()->json(['message' => 'Logged out'], 200);
    }
}
