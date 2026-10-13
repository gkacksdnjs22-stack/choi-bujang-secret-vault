# 8단계 기본 판정기 재검토

이번 수정은 로컬 작업만이며 배포·커밋·제출하지 않았습니다.

## 확인한 공식 근거

- https://github.com/ChoiTimo/aleph-defense-starter/blob/main/docs/DECIDER_REQUEST.md : 요청은 18항목이고 subjectId는 Supabase 사용자 ID가 아닙니다. 소유자 필드나 연결 API는 제공되지 않습니다.
- https://github.com/ChoiTimo/byteback-sample-pass/blob/main/src/decider.mjs : 기본 함수는 구역을 검사하고 메모 주인 비교는 엔진·서버 함수가 맡는다고 명시합니다.
- https://github.com/ChoiTimo/byteback-sample-pass/blob/main/README.md : 엔진 코드는 표본에 포함되어 있지 않습니다. 표본은 통과 목표이며 실제 통과를 보장하지 않습니다.
- 방어전 8단계 제작 2는 판정기 구역 규칙, 제작 3은 최종 API의 검증 사용자와 저장된 소유자·강사 권한 대조를 요구합니다.

## 수정과 확인

기본 decide()는 상대 모듈이나 서버 환경변수 없이 구역 판정을 실행합니다. 공식 연습의 /notes/demo 읽기와 같은 깊이의 정확한 자료 단건 읽기·수정을 허용합니다. 미등록 기기, 잘못된 계약, 오래된 요청, 전체 목록, 예약된 기능 경로, 쿼리 기능 선택, 알 수 없는 경로와 공지 수정은 거부합니다. 이전 복합 위험 재확인 규칙을 유지합니다.

기본 함수의 구역 허용은 소유권 허가를 뜻하지 않습니다. 사용자·기기와 소유권을 대조하는 createEngineDecision/runtimeDecision 및 최종 API는 유지했습니다. 서버 등록·만료·소유권·강사 권한 조건은 제거하지 않았습니다. 기본 함수만 주체를 바꿔 호출하면 메모 소유권을 구별할 수 없으며 이 한계를 테스트에 명시했습니다.

별도 권한을 주입하던 decider:test와 fixture:7은 실제 기본 함수를 호출합니다. 단독 파일 격리 실행에서도 같은 정상 허용·구역 거부·복합 위험을 시험합니다. 가상 DB 시험은 서버 소유권 집행 단계에서 A/B 본인 허용과 양방향 타인 거부를 확인합니다.

## 남은 한계

실제 ALEPH 엔진의 주체·기기 연결 등록 API/정책 공급 규약은 공개 안내와 저장소에서 찾지 못했습니다. 이를 연결했다고 주장하지 않습니다. 기본 함수만으로 타인 소유권을 판단했다거나 심판의 두 실패 코드가 해결됐다고 주장하지 않습니다. 실제 배포/심판 재시험은 미실행입니다.

검토 명령: npm run decider:test, npm run fixture:7, npm run test:step8.
