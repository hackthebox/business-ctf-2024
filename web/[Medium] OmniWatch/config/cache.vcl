vcl 4.0;

backend default1 {
    .host = "127.0.0.1";
    .port = "3000";
}

backend default2 {
    .host = "127.0.0.1";
    .port = "4000";
}

sub vcl_hash {
    hash_data(req.http.CacheKey);
    return (lookup);
}

sub vcl_synth {
    if (resp.status == 301) {
        set resp.http.Location = req.http.Location;
        set resp.status = 301;
        return (deliver);
    }
}

sub vcl_recv {
    if (req.url ~ "^/controller/home"){
        set req.backend_hint = default1;
        if (req.http.Cookie) {
            return (hash);
        }
    } else if (req.url ~ "^/controller") {
        set req.backend_hint = default1;        
    } else if (req.url ~ "^/oracle") {
        set req.backend_hint = default2;
    } else {
        set req.http.Location = "/controller";
        return (synth(301, "Moved"));
    }
}

sub vcl_backend_response {
    if (beresp.http.CacheKey == "enable") {
        set beresp.ttl = 10s;
        set beresp.http.Cache-Control = "public, max-age=10";
    } else {
        set beresp.ttl = 0s;
        set beresp.http.Cache-Control = "public, max-age=0";
    }
}

sub vcl_deliver {
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }

    set resp.http.X-Cache-Hits = obj.hits;
}
