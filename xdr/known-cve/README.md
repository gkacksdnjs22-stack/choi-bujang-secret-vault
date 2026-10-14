# 알려진 취약점 악용 보너스

공식 `ChoiTimo/aleph-defense-starter`의 main 저장점 `2cd777b452525b95e29f12f2c76d9190a594ec23`에서 시험 경보를 그대로 가져왔습니다. SHA-256은 `db2dad63fd08f4da6de25135c1744357809290cd3f960570bb1eb5a848cde046`입니다. 경보는 수업용이며 실제 침입 로그가 아닙니다. 원격 조회 문자열은 평가·호출·변형하지 않습니다.

`read-alerts.mjs`는 시각·주소·가상 계정·수준·설명 5개 필드만 출력하고 비밀값처럼 보이는 문구를 가립니다. 계정 필드가 없는 경보는 빈 문자열입니다. 판단 파일은 이 읽기 모듈을 불러오지 않습니다.

`patterns.json`의 근거는 [Apache CVE-2021-44228 설명](https://logging.apache.org/security.html#CVE-2021-44228)과 [MITRE T1190](https://attack.mitre.org/techniques/T1190/)입니다. `decide.mjs` 상수는 실제 요청의 완전한 원격 조회 구문과 경보 수준을 함께 대조합니다. 취약점 이름·조회 일부·도구 흔적만으로 차단하지 않습니다. 임계값 0.85/0.5는 과제 지정이며 세부 확신도와 수준 조합은 로컬 정책입니다. 단일 파일에 import·파일 입출력·외부 호출이 없습니다. 이 패턴 검사는 Log4j 패치나 모든 우회 변형의 탐지를 대신하지 않습니다.

## 확인 명령

`node scripts/check-xdr-known-cve.mjs`

공식 시험 경보는 block8 / alert8 / record8이며 정상8건의 오차단은0입니다. 단독 파일 실행, 경보 ID 변경에 무관한 판정, 원본 불변, 비밀값 가림, 실제 기본 판정 함수의 허용·거부·추가 인증 보존, 만료 뒤 허용을 로컬에서 검증합니다.

`npm run xdr:run -- known-cve`로 `result.json`을 재생성합니다. 이 결과는 수업용 입력에 대한 자기 점검이며 심판 결과나 실제 운영 차단 증거가 아닙니다.

## 거부 규칙 연결

`respond({alerts, decideBase, outputDirectory, clock, logFile})`가 block 후보에만 만료와 근거 경보 번호를 넣고, block/alert 결과를 `xdr/alerts.log`에 쌓습니다. 원문 요청·비밀값은 로그와 규칙에 쓰지 않습니다. 기본 판정은 먼저 실행하고 기존 deny/step_up을 그대로 보존합니다.

거부 범위는 신뢰된 전송 출처의 주소와 해당 요청 지문이 모두 일치할 때만 적용합니다. 같은 주소라도 정상 요청의 지문은 허용합니다. 운영 연결자가 확인한 `sourceAddress`, `httpObservation`(url/useragent), 등록된 `registeredDenyReasonCode`를 별도 전송 문맥으로 받아야 합니다. 이 문맥은 학생이 설계한 로컬 어댑터의 인자이며 공식18필드 판정 요청에 새 필드를 넣는 것이 아닙니다. 브라우저 본문·헤더를 검증 없이 이 문맥으로 넘기면 안 됩니다.

실제 기본 판정 함수와 이 어댑터의 연결을 시험했으며, 운영 엔진의 사건 전달이나 실접속 차단은 연결하지 않았습니다. 기존 `src/decider.mjs`와 다른 보너스는 변경하지 않았습니다.
