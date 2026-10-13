# 9단계 탐지 연습 사건 계약

`npm run detect:test`는 학생이 작성한 `src/detect.mjs`의 `detect(events)`에 가상 조회 사건을 전달합니다. 각 사건은 다음 세 값만 가집니다.

```js
{ at: '2026-10-01T00:00:00.000Z', method: 'GET', identity: { sub: 'learner_fixture' } }
```

같은 `identity.sub`의 `GET` 사건이 어느 10분 구간에서든 **120건을 넘을 때만** `{ action: 'propose_revocation', reasonCode: 'burst_read', subject: '해당 sub' }`를 돌려줍니다. 그 밖에는 `{ action: 'observe' }`입니다. 정확히 120건은 회수 제안 대상이 아닙니다. 다른 사용자의 사건을 합산하거나 10분 밖의 사건을 같은 묶음으로 세지 않습니다.

이 파일의 사건 모양은 **로컬 연습용**입니다. 브라우저가 보낸 사용자 번호를 신원으로 취급하지 않습니다. 운영 반 엔진이 검증한 사건을 전달하고 회수 제안을 집행하는 경로는 별도로 연결·시험해야 합니다. 이 명령의 통과를 실제 접속 차단이나 심판 판정으로 표시하지 않습니다.

## 별도 로컬 기기 복합 연습

9단계 웹 안내의 기기별 복합 조건은 기본 3항목 계약에 정의되어 있지 않습니다. 그래서 `detectDeviceEvents(events)`를 별도 로컬 연습 함수로 두었습니다. 이는 제공 엔진 계약의 확장이 아닙니다.

합성 입력은 `{at, subjectId, deviceId, method, decision, network, source}`이며 source는 `local_virtual_fixture`, 기기는 16자리 소문자 16진수입니다. 사용자·기기별 허용된 GET을 따로 세고, 같은 10분 미만 창 안에 121건 이상과 `network:unusual`이 함께 있을 때만 `{action:'propose_revocation', reasonCode:'burst_read', subject, deviceId}`를 제안합니다. 지역은 확정 조건으로 사용하지 않습니다. 정상 네트워크·다른 기기·다른 사용자는 섞지 않습니다.

이 함수는 실제 회수 API를 만들거나 등록부를 변경하지 않습니다. 토큰·본문·실명은 입력에 요구하지 않으며 반환하지 않습니다. `npm run test:step9`에서 로컬 회수 모델을 시험하되 실제 운영 집행과 시간 측정은 미확인으로 남깁니다.
