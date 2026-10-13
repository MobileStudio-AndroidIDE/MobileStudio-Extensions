# Line Counter

파일을 저장할 때 열려 있는 파일의 줄 수를 집계해 토스트로 보여주는 코드 확장입니다.

## 동작
- `onFileSave` 훅에 반응
- 총 줄 / 코드 / 주석(`//`, `/* */`, `#`) / 공백 줄을 각각 집계

## 요구 권한
- `editor` — 현재 파일 읽기 및 토스트 표시

## 빌드
Java 소스 → `javac`(app classes.jar + android.jar) → `d8` → `classes.dex`
