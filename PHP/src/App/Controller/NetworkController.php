<?php

namespace App\Controller;

use Slim\Http\Request;
use Slim\Http\Response;

class NetworkController extends Controller
{
    public function traceRt(Request $request, Response $response)
    {
        $data   = json_decode($request->getBody());

        $dest   = empty($data->dest)    ? '' : escapeshellarg($data->dest);
        $proto  = empty($data->proto)   ? '' : "--proto ".escapeshellarg($data->proto)." ";
        $port   = empty($data->port)    ? '' : "--porta ".escapeshellarg($data->port)." ";
        $ttl    = empty($data->ttl)     ? '' : "--ttl ".escapeshellarg($data->ttl)." ";
        $hops   = empty($data->hops)    ? '' : "--hops ".escapeshellarg($data->hops)." ";

        $opts       = $proto.$port.$ttl.$hops;
        $traceRt    = __DIR__."/../../../../Python/traceroute.py ";

        $cmd    = "sudo python3 ".$traceRt.$opts.$dest;
        $result = shell_exec($cmd);

        return $response->write($result);
    }

}
