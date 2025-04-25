# IP HASH (NGINX_DOCUMENTATION)(https://nginx.org/en/docs/http/ngx_http_upstream_module.html#ip_hash)

 The server to which a request is sent is determined from the client IP address. In this case, either the first three octets of the IPv4 address or the whole IPv6 address are used to calculate the hash value. The method guarantees that requests from the same address get to the same server unless it is not available.

upstream backend {
    ip_hash;

    server backend1.example.com;
    server backend2.example.com;
    server backend3.example.com down;
    server backend4.example.com;
}

# Round Robin

Requests are distributed evenly across the servers, with server weights taken into consideration. This method is used by default (there is no directive for enabling it):

upstream backend {
   # no load balancing method is specified for Round Robin
   server backend1.example.com;
   server backend2.example.com;
}

# Least Connections (nginx rr)(https://nginx.org/en/docs/http/ngx_http_upstream_module.html#least_conn)

A request is sent to the server with the least number of active connections, again with server weights taken into consideration:

upstream backend {
    least_conn;
    server backend1.example.com;
    server backend2.example.com;
}

# Hash (nginx gh)(https://nginx.org/en/docs/http/ngx_http_upstream_module.html#hash)

The server to which a request is sent is determined from a user‑defined key which can be a text string, variable, or a combination. For example, the key may be a paired source IP address and port, or a URI as in this example:

upstream backend {
    hash $request_uri consistent;
    server backend1.example.com;
    server backend2.example.com;
}
