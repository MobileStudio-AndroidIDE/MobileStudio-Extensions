# MobileStudio-Extensions

MobileStudio의 **공식 Extension Registry** — GitHub 저장소 하나로 확장을 등록하고 배포합니다.
별도의 Firebase/Supabase 서버 없이 GitHub만 사용합니다.

## 구조

```
MobileStudio-Extensions/
├── README.md                  # 이 파일
├── registry.json              # 확장 인덱스 (앱이 이 파일을 읽어 확장 목록 로드)
├── schema/
│   └── extension.schema.json  # extension.json JSON Schema
├── extensions/
│   └── example/               # 확장 예제 (ID당 폴더 하나)
│       ├── extension.json
│       └── README.md
├── scripts/
│   └── validate.py            # 검증 스크립트 (GitHub Actions에서 사용)
└── .github/
    └── workflows/
        └── validate-extension.yml
```

## 확장 등록 방법 (Fork + Pull Request)

1. 이 저장소를 **Fork** 합니다.
2. `extensions/<내확장ID>/` 폴더를 만들고 `extension.json`과 `README.md`를 추가합니다.
3. `registry.json`의 `extensions` 배열에 확장 항목을 추가합니다.
4. **Pull Request**를 생성합니다.
5. GitHub Actions가 자동으로 검증합니다:
   - JSON Schema 검증
   - extension ID / SemVer 버전 검증
   - 중복 ID/버전 검사
   - 필수 파일 검사
   - 확장 파일 크기 검사
   - 확장 구조 검사
   - registry.json 검증
6. 검증을 통과하면 maintainer가 merge합니다.

## extension.json 필드

| 필드 | 필수 | 설명 |
|---|---|---|
| `id` | ✅ | 고유 ID (소문자/숫자/`-`/`_`/`.`), 3-64자 |
| `name` | ✅ | 확장 이름 |
| `version` | ✅ | SemVer (MAJOR.MINOR.PATCH) |
| `author` | ✅ | 작성자 (GitHub 사용자명) |
| `description` | ✅ | 설명 |
| `type` | ✅ | `syntax` / `theme` / `template` / `toolchain` / `language` / `formatter` / `linter` / `snippets` / `plugin` |
| `minMobileStudioVersion` | ✅ | 필요한 최소 MobileStudio 버전 (SemVer) |
| `download` | ✅ | 확장 아카이브 URL (**HTTPS만**) |
| `icon` | ❌ | 아이콘 URL (HTTPS) |
| `permissions` | ❌ | 필요 권한 (`filesystem` / `network` / `shell` / `terminal` / `editor` / `build` / `adb`) |

## 앱 측 로드

MobileStudio는 `registry.json`을 읽어 확장 목록을 표시하고, 사용자가 설치를
선택하면 `download` URL에서 아카이브를 내려받아 설치합니다.
