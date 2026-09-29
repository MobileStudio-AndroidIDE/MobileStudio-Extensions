# Example Extension

MobileStudio extension manifest 예제입니다.

## 등록 방법

1. 이 폴더를 복사해 `extensions/<내확장ID>/`로 만듭니다.
2. `extension.json`의 필드를 확장에 맞게 수정합니다.
   - `id`는 폴더 이름과 동일해야 합니다.
   - `download`는 HTTPS URL만 허용됩니다.
3. `registry.json`에 항목을 추가합니다.
4. Pull Request를 생성하면 GitHub Actions가 자동 검증합니다.

## 검증 규칙

- `id`: 소문자/숫자/`-`/`_`/`.` 3-64자, 첫 글자는 알파벳/숫자
- `version` / `minMobileStudioVersion`: SemVer
- 중복 ID(같은 버전) 불가
- 폴더에는 `extension.json` + `README.md` 필수
- 확장 폴더 전체 크기 50MB 이하, 개별 파일 10MB 이하
