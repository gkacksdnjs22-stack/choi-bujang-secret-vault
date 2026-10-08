# 무차별 로그인 보너스 작업 상태

공식 시작 틀 main의 커밋 `8a0927400ec0d0a8ff08146db773fec80fb6d216`에서
`xdr/README.md`, `xdr/fixtures/brute-force.json`, `scripts/xdr-run.mjs`를 가져왔습니다.
경보 원본은 수정하지 않았습니다. 다른 보너스는 아직 구현하지 않았습니다.

읽기 모듈은 시각·출발 주소·계정·규칙 수준·설명만 반환하며 비밀값 패턴을 가립니다.
patterns.json의 근거는 MITRE ATT&CK T1110입니다. 수치 기준은 수업 경보용
로컬 정책이며 MITRE가 권고한 특정 수치라고 주장하지 않습니다.
판단은 경보 ID나 정답표를 사용하지 않습니다.

## 실행 및 실제 확인

`node scripts/check-xdr-brute-force.mjs`

공식 경보 28건: block 10, alert 9, record 9. 경보 설명상 정상 9건의 block은 0건입니다.
Jev 오류·시간 초과·잘못된 응답은 alert로 처리합니다. 정상 경보는 Jev에 보내지 않습니다.
차단 후보는 15분 만료와 근거 경보 번호를 포함하며, 정상 주소·만료된 차단은
로컬 연결 도우미에서 차단하지 않는 것을 검증했습니다.
`npm run xdr:run -- brute-force`로 공식 실행기를 사용해 result.json을 갱신합니다.
추가 검증 도구는 자료 본문이나 자격 증명 없이 alerts.log를 생성합니다.

## 아직 연결되지 않은 부분

Jev 공식 API 계약과 설정이 없어 실제 AI 호출은 연결하지 않았습니다.
createDecider의 askJev 주입 지점을 마련했으며 기본값은 미연결 상태의 alert입니다.

기존 src/decider.mjs는 starter.deny 초기 틀입니다. docs/DECIDER_REQUEST.md의
18개 요청 필드에는 출발 IP가 없습니다. 따라서 deny-rules.mjs는 엔진이 확인한
출발 주소를 별도로 받는 연결 준비 부품이며 운영 판정기에 아직 꽂지 않았습니다.
브라우저 값이나 임의 요청 필드를 만들어 실제 신뢰 정보처럼 취급하지 않습니다.
실제 정상 요청 통과·공격 요청 차단은 검증되지 않았으며 운영 연결 완료로 보고하지 않습니다.

기존 메모 API·UI·DB·판정기 규칙은 변경하지 않았습니다.
3단계 인증 거부와 4단계 A/B 소유자 로컬 회귀 검사는 통과했습니다.
커밋·푸시·배포·제출 칸 입력·심판 제출은 하지 않았습니다.
