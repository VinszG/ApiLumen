<?php

namespace App\Http\Controllers;

use App\Models\Lending;
use Illuminate\Http\Request;
use App\Helpers\ApiFormatter;
use Illuminate\Support\Facades\Validator;
use App\Models\StuffStock;
use Illuminate\Support\Str;

class LendingController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'logout']]);
    }

    public function index()
    {
        try {
            $getLending = Lending::with('stuff', 'user')->get();

            return ApiFormatter::sendResponse(200, true,'Successfully Get All Lending Data', $getLending);
        } catch (\Exception $e) {
            return ApiFormatter::sendResponse(400, false,$e->getMessage());
        }
    }

    public function create()
    {
        //
    }

    public function store(Request $request)
{
    try {
        $this->validate($request, [
            'stuff_id' => 'required',
            'date_time' => 'required',
            'name' => 'required',
            'user_id' => 'required',
            'notes' => 'required',
            'total_stuff' => 'required',
        ]);

        $createLending = Lending::create([
            'stuff_id' => $request->stuff_id,
            'date_time' => $request->date_time,
            'name' => $request->name,
            'user_id' => $request->user_id,
            'notes' => $request->notes,
            'total_stuff' => $request->total_stuff,
        ]);

       
        return ApiFormatter::sendResponse(200, true, 'Successfully Create A Lending Data', $createLending);
    } catch (\Exception $e) {
   
        return ApiFormatter::sendResponse(400, false, $e->getMessage());
    }
}

    public function show($id)
{
    try {
        $getLending = Lending::where('id', $id)->with('stuff', 'user', 'restoration')->first();

        if (!$getLending) {
            return ApiFormatter::sendResponse(404, false, 'Data Lending Not Found');
        } else {
            return ApiFormatter::sendResponse(200, true, 'Successfully Get A Lending Data', $getLending);
        }
    } catch (\Exception $e) {
        return ApiFormatter::sendResponse(400, $e->getMessage());
    }
}


    public function edit(Lending $lending)
    {
        //
    }

   
    public function update(Request $request, $id)
    {
        $validator = Validator::make($request->all(), [
            'stuff_id' => 'required',
            'date_time' => 'required|date',
            'name' => 'required|string',
            'user_id' => 'required',
            'notes' => 'required|string',
            'total_stuff' => 'required|integer',
        ]);

        if ($validator->fails()) {
            return ApiFormatter::sendResponse(400, false, $validator->errors()->first());
        }

        try {
            $getLending = Lending::find($id);
            if (!$getLending) {
                return ApiFormatter::sendResponse(404, false, 'Data Lending Not Found');
            }

            // Update stuff stock
            $getCurrentStock = StuffStock::where('stuff_id', $getLending->stuff_id)->first();
            $getStuffStock = StuffStock::where('stuff_id', $request->stuff_id)->first();

            if ($request->stuff_id == $getLending->stuff_id) {
                $getCurrentStock->update([
                    'total_available' => $getCurrentStock->total_available + $getLending->total_stuff - $request->total_stuff
                ]);
            } else {
                $getCurrentStock->update([
                    'total_available' => $getCurrentStock->total_available + $getLending->total_stuff
                ]);

                if ($getStuffStock) {
                    $getStuffStock->update([
                        'total_available' => $getStuffStock->total_available - $request->total_stuff
                    ]);
                }
            }

            // Update lending
            $getLending->update($request->all());

            $getUpdateLending = Lending::where('id', $id)->with('stuff', 'user', 'restoration')->first();

            return ApiFormatter::sendResponse(200, true, 'Successfully Update A Lending Data', $getUpdateLending);
        } catch (\Exception $e) {
            return ApiFormatter::sendResponse(400, false, $e->getMessage());
        }
    }
    public function destroy($id)
    {
        try {
            $lending = Lending::find($id);
            if (!$lending) {
                return ApiFormatter::sendResponse(404, 'Data Lending Not Found');
            }

            $lending->delete();
            return ApiFormatter::sendResponse(200, true,'Successfully Delete A Lending Data');
        } catch (\Exception $e) {
            return ApiFormatter::sendResponse(400, false,$e->getMessage());
        }
    }
    public function deleted()
{
    try {
        $trashedLendings = Lending::onlyTrashed()->with('stuff', 'user')->get();
        return ApiFormatter::sendResponse(200, true, 'Successfully Get All Trashed Lending Data', $trashedLendings);
    } catch (\Exception $e) {
        return ApiFormatter::sendResponse(400, false, $e->getMessage());
    }
}
public function restore($id)
{
    try {
        $lending = Lending::onlyTrashed()->find($id);
        if (!$lending) {
            return ApiFormatter::sendResponse(404, false, 'Data Lending Not Found');
        }

        $lending->restore();
        return ApiFormatter::sendResponse(200, true, 'Successfully Restored Lending Data');
    } catch (\Exception $e) {
        return ApiFormatter::sendResponse(400, false, $e->getMessage());
    }
}

public function permanentDelete($id)
{
    try {
        $lending = Lending::onlyTrashed()->find($id);
        if (!$lending) {
            return ApiFormatter::sendResponse(404, false, 'Data Lending Not Found');
        }

        $lending->forceDelete();
        return ApiFormatter::sendResponse(200, true, 'Successfully Permanently Deleted Lending Data');
    } catch (\Exception $e) {
        return ApiFormatter::sendResponse(400, false, $e->getMessage());
    }
}

public function permanentDeleteAll()
{
    try {
        $trashedLendings = Lending::onlyTrashed()->get();
        if ($trashedLendings->isEmpty()) {
            return ApiFormatter::sendResponse(404, false, 'No Trashed Lending Data Found');
        }

        Lending::onlyTrashed()->forceDelete();
        return ApiFormatter::sendResponse(200, true, 'Successfully Permanently Deleted All Trashed Lending Data');
    } catch (\Exception $e) {
        return ApiFormatter::sendResponse(400, false, $e->getMessage());
    }
}


}