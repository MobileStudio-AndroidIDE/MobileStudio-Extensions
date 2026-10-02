# MobileStudio-Extensions

MobileStudio의 **공식 Extension Registry** — GitHub 저장소 하나로 확장을 등록하고 배포합니다.
확장 목록의 원본은 **GitHub Releases**입니다 (커밋된 인덱스 파일 없음: `repository.json` / `registry.json` 폐지).

## 구조

```
MobileStudio-Extensions/
├── README.md                  # 이 파일
├── schema/
│   └── extension.schema.json  # extension.json JSON Schema
├── extensions/                # 확장 소스 (ID당 폴더 하나, PR로 추가)
│   └── example/
│       ├── extension.json
│       └── README.md
├── scripts/
│   ├── validate.py            # 검증 스크립트 (서버/CI 공용)
│   ├── security_scan.py       # 다단계 보안 스캔 (.msext/폴더)
│   └── gen_registry.py        # (폐기) 더 이상 인덱스를 만들지 않음
├── server/                    # 업로드/배포 API (FastAPI) — 자세한 내용은 server/README.md
└── .github/workflows/
    └── validate-extension.yml # PR 검증 + 보안 스캔 + 스캔 결과 커밋
```

## 등록 방법 A: 업로드 API (권장)

MobileStudio 앱 또는 `server/`의 API로 `.msext` 패키지를 업로드하면 서버가 전체를 처리합니다:

1. 업로드 게이트 (`.msext` 전용, ZIP 구조/용량/zip-slip/symlink 검사)
2. `scripts/security_scan.py` + `scripts/validate.py`
3. `extensions/<id>/` 변경 브랜치 → **Pull Request** 생성
4. GitHub Actions가 PR에서 다시 검증 (scan-results/queue.json 커밋)
5. 검증 통과 → PR merge
6. **Draft Release** 생성 → `.msext` asset 업로드 → 공개 (본문 = extension.json JSON)
7. 상태가 `published`가 되며 즉시 레지스트리에 노출

실패한 제출은 어떤 경우에도 Release에 도달하지 않습니다.

## 등록 방법 B: 수동 Pull Request

1. 이 저장소를 **Fork** 합니다.
2. `extensions/<내확장ID>/` 폴더를 만들고 `extension.json`과 `README.md`를 추가합니다.
3. **Pull Request**를 생성합니다.
4. GitHub Actions가 자동으로 검증합니다:
   - JSON Schema 검증 / extension ID / SemVer / 중복 버전
   - 필수 파일·크기·구조 검사
   - `.msext` 보안 스캔 (파일 패키지인 경우)
5. 검증을 통과하면 maintainer가 merge합니다.
6. Release를 직접 만들면 레지스트리에 표시됩니다 (아래 규칙).

## Release 규칙 (레지스트리 원본)

| 항목 | 규칙 |
|---|---|
| tag | `<extension-id>-v<version>` (예: `com.test.demo-v1.0.0`) |
| asset | `<extension-id>-v<version>.msext` (`.msext`만 확장으로 인식) |
| body | extension.json 내용의 JSON (`sha256`, `size`, `download` 포함) |
| draft | 제외 (공개된 Release만 표시) |
| prerelease | `?include_prerelease=true`일 때만 표시 |
| 중복 ID | 가장 높은 SemVer만 표시 |

## extension.json 필드

| 필드 | 필수 | 설명 |
|---|---|---|
| `id` | ✅ | 고유 ID (소문자/숫자/`-`/`_`/`.`), 3-64자 |
| `name` | ✅ | 확장 이름 |
| `version` | ✅ | SemVer (MAJOR.MINOR.PATCH) |
| `author` | ✅ | 작성자 (GitHub 사용자명) |
| `description` | ✅ | 설명 |
| `download` | ✅ | `.msext` 다운로드 URL (**HTTPS만**) |
| `minStudioVersion` | ✅ | 필요한 최소 MobileStudio 버전 (SemVer) |
| `type` | ❌ | `syntax` / `theme` / `template` / `toolchain` / `language` / `formatter` / `linter` / `snippets` / `plugin` |
| `minMobileStudioVersion` | ❌ | `minStudioVersion` 별칭 (호환용) |
| `icon` | ❌ | 아이콘 URL (HTTPS) |
| `permissions` | ❌ | 필요 권한 (`filesystem` / `network` / `shell` / `terminal` / `editor` / `build` / `adb`) |
| `size`, `sha256` | ❌ | 배포 흐름이 자동으로 채움 |

## 앱 측 로드

MobileStudio는 GitHub Releases API(`GET /repos/<owner>/<repo>/releases`)로 확장
목록을 읽고 ETag/`If-None-Match` 캐싱으로 재요청을 줄입니다. 사용자가 설치를
선택하면 각 Release의 `.msext` asset URL에서 내려받아 설치합니다.

## 로컬 검증

```bash
python scripts/validate.py                     # 저장소 전체 검증
python scripts/security_scan.py extensions/example
cd server && pytest                            # 업로드 API 테스트
```
