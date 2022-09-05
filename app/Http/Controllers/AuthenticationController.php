<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class AuthenticationController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        
        $user = User::create([
            "name" => $request->input('name'),
            "email" => $request->input('email'),
            "password" => bcrypt($request->input('password')),
        ]);
        $user->save();
        $token = $user->createToken("30JKDLHF94JKD89F")->plainTextToken;
        
        return response([$user, $token]);
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        $user = User::where('email', $request->input("email"))->first();
        if(!$user || !Hash::check($request->input("password"), $user->password)){
            return response("No authorized", 401);
        }
        $response = [
            "user" => $user,
            "token" => $user->createToken("30JKDLHF94JKD89F")->plainTextToken
        ];

        return response($response);
    }

    public function edit(Request $request)
    {
        $user = User::where('email', $request->input("email"))->first();
        if(!$user || !Hash::check($request->input("password"), $user->password)){
            return response("No authorized", 401);
        }
        $response = [
            "user" => $user,
            "token" => $user->createToken("30JKDLHF94JKD89F")->plainTextToken
        ];

        return response($response);
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        return response([auth()->user(), $id]);
        //auth()->user()->tokens()->delete();
    }
}
