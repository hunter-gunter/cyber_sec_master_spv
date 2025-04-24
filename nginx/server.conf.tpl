server {
  listen 80;
  listen [::]:80;

  server_name ${subdomain}.hackonthebox.fr;
  
  location / {
    proxy_pass ${tagetIp};
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; 
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
  }

  # Set https certificate variables at some point too.
}