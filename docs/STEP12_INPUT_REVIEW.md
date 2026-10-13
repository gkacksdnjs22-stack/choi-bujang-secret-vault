# 12단계 제출 입력·집계 규약 대조 (2026-10-13)

조사 대상은 eec2dd5663e854e9ea6c41c7a175fbcbc2b6b7b3의 45점 S12_UNRUN_COUNTED입니다. 최고점53은 이전 판정입니다. 이번 조사에서 보호 API·배포·제출은 변경하지 않았습니다.

## 확인한 공개 근거

- https://github.com/ChoiTimo/byteback-sample-pass 의 현재 README, scripts/bundle.mjs, src/attack-check.mjs, api/checks.js, public/app.js를 대조했습니다.
- 공식 README는 심판이 격리된 제출 사본에서 새 묶음을 만들며 과거 영수증을 새 실행 근거로 쓰지 않는다고 명시합니다.
- 공식 bundle은 HEAD와 origin을 읽고 실제 GET 점검을 수행한 후 artifacts/submission.json을 생성합니다. stage/result는 자기보고 요약이며 실행 영수증을 대신하지 않습니다.
- 공식 api/checks.js는 이 artifacts/submission.json을 매번 읽어 total, result=blocked 건수, result=not_run 건수, failed를 계산합니다. public/app.js는 같은 API 수치를 표시합니다.
- 공식 저장소에 이미 들어 있는 submission.json은 예전 schema와 관측 문구의 과거 파일입니다. 현재 실행 계약과 혼동하거나 그대로 복사하지 않습니다.
- 공개 포털 assets/defense-ui/room.js와 defense-campaign-live.js도 읽었습니다. 제출 폼은 deploymentUrl/repoUrl/evidenceNote 및 bundleNotes(explanation, blockedAt)를 전달합니다. 로컬 submission.json을 이 폼에서 업로드하는 구조가 아닙니다. 비밀 세션이나 사용자 토큰은 읽지 않았습니다.
- 공개 소유자 저장소 목록과 미통과 표본도 확인했습니다. 공개 저장소에서 S12_UNRUN_COUNTED를 평가하는 심판 서버 코드는 확인하지 못했습니다.

## 우리 코드의 확인된 차이

우리 scripts/bundle.mjs는 artifacts/submission.json을 생성하지만 scripts/build-public.mjs는 별도 artifacts/checks.json을 만듭니다. api/checks.mjs는 checks.json만 읽습니다. 두 파일은 같은 함수로 계산되어 평소 수치가 같아도 실행 시점·환경·파일이 다릅니다. 심판이 submission.json을 새로 생성하거나 미실행 결과가 달라져도 API가 그 결과를 재독하지 않습니다. 이전 검증은 동일 응답 환경의 합계 일치만 확인하여 이 연결 차이를 놓쳤습니다.

## 로컬 재현 결과

실제 개인정보 없는 기존 점검 기록을 임시로 사용했습니다. checks.json에는 기존18항목(차단13/미실행5)을 두고, submission.json의18항목을 모두 observed/result=not_run으로 변경했습니다. API는 새 submission.json의 차단0/미실행18을 읽지 않고 계속 차단13/미실행5를 반환했습니다. 두 파일은 finally에서 원래 상태로 복원했고 Git 기능 파일 변경은 없습니다. 실제 서버·DB 자료는 변경하지 않았습니다.

이 재현은 **새 실행 기록과 API 집계가 분리되는 구조적 문제**를 증명합니다. 실제 심판 실행이18항목 모두 미실행이었다는 뜻은 아니며, 정확한 S12_UNRUN_COUNTED 내부 원인으로 확정하지 않습니다. 심판의 항목별 실행 영수증은 현재 화면에 공개되지 않았습니다.

## 다음 수정 방향

공식 규약처럼 현재 실행에서 생성한 submission.json을 집계의 단일 원본으로 연결해야 합니다. 빌드 점검의 과거 합계로 현재 실행을 대체하지 않습니다. 단독 실행에서 새 제출 기록을 생성한 뒤 API가 재독했을 때 blocked/notRun 변화가 반영되는 회귀 시험이 필요합니다. 정상 허용·가상 금지 조건·실제 자료 요청·공식41종 결과의 구분은 유지하며, 미실행을 임의 차단으로 고치거나 심판 예외 권한을 만들지 않습니다.

사용자는 원인 조사만 요청했습니다. 수정·배포·재제출은 이번 조사에서 수행하지 않았습니다.
