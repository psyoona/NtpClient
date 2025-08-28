# NtpClient

외부 시계 서버(NTP/HTTP)를 이용해 **UTC 기준 시간**을 안전하게 가져오는 C# 유틸리티입니다.
운영 환경에서 로컬 시스템 클록(`DateTime.UtcNow`)을 신뢰할 수 없을 때, **네트워크 기준 시각**을 조회하는 데 사용하세요.

> ⚠️ 시스템 시간 자체를 변경(동기화)하는 기능은 **운영 정책·권한 이슈**가 크므로 **기본값은 “조회만”** 합니다. 필요 시 Windows 전용 동기화 코드를 옵션으로 추가할 수 있습니다(아래 참조).

---

## ✨ 주요 기능

* **다중 NTP 서버 질의**: `time.windows.com`, `time.google.com`, `time.cloudflare.com`, `pool.ntp.org`
* **IPv4 강제 + UDP/123** 사용 (기업망 IPv6/방화벽 이슈 회피)
* **타임아웃/재시도** 지원
* **HTTP Date 헤더 폴백**(옵션): UDP/123 차단 환경에서도 외부 기준 UTC 확보 가능
* **순수 C# 구현**: 외부 라이브러리 미사용

---

## 🧱 지원 환경

* .NET 8 이상 권장
* Windows / Linux / macOS
  * **NTP 조회**는 크로스플랫폼
  * **시스템 시간 변경**은 **Windows 전용 + 관리자 권한 필요**

---

## 📦 설치/빌드

```bash
# 예시
dotnet new console -n NtpClientSample
cd NtpClientSample
# UtcTimeService.cs 추가 후
dotnet build
dotnet run
```

프로젝트에 제공된 `UtcTimeService` 클래스를 그대로 포함하세요.

---

### HTTP 폴백 활성화 (옵션)

현재 코드에서는 폴백 호출이 주석 처리되어 있습니다. **아래 한 줄을 주석 해제**하세요.

```csharp
// 2) 폴백: HTTPS Date 헤더 (대부분의 환경에서 443은 허용)
if (!ntpUtc.HasValue)
{
    ntpUtc = await QueryHttpDateFallbackAsync(ct).ConfigureAwait(false);
}
```

> 정확도: NTP(밀리초\~수십 ms) > HTTP Date 헤더(초 단위).
> 방화벽·보안 정책으로 UDP/123이 막힌 환경에서 폴백을 권장합니다.

---

## 🔧 구성 포인트

* **NTP 서버 목록 변경**: `UtcTimeService.NtpServers` 배열 수정
* **타임아웃/재시도**: `GetUtcNowAsync(ntpTimeoutMs, ntpRetries)` 인자 조정

  * 고지연 환경: `ntpTimeoutMs`를 5000\~8000ms로 늘리세요.
* **IPv4 강제**: `AddressFamily.InterNetwork` 사용 (필요 시 IPv6 로직 추가 가능)

---

## 🖥️ (옵션) Windows 시스템 시계 동기화

> **권장 정책**: 도메인/서버는 보통 `w32time`(그룹 정책)으로 관리합니다.
> 애플리케이션이 **직접 시스템 시간을 바꾸는 것은 가급적 지양**하고, 외부 UTC를 가져와 **오프셋 계산**만 비즈니스 로직에 적용하는 패턴을 추천합니다.

그래도 **승인된 유지보수 도구**로 쓰고자 한다면:

1. **관리자 권한으로 프로세스 실행**(UAC 승격 필수)
2. 실행 계정에 **“시스템 시간 변경(SeSystemtimePrivilege)”** 권한 존재 확인
   * `secpol.msc` → 로컬 정책 → 사용자 권한 할당 → *시스템 시간 변경*
   * 도메인 환경: GPMC로 GPO 배포
3. (선택) **드리프트 임계치**를 두고 큰 차이일 때만 변경

예시 메서드는 다음을 참고해 프로젝트에 추가하세요(Windows 전용, Win32 API `SetSystemTime` 사용).

> 이 코드는 이전 안내 메시지에서 제공한 `SyncSystemClockAsync` 구현을 그대로 사용하시면 됩니다.
> 실패 코드 **1314**는 권한 부재입니다(아래 TroubleShooting 참고).


### 운영 대안 (CLI, 승격 필요)

```bat
w32tm /config /manualpeerlist:"time.google.com time.cloudflare.com" /syncfromflags:manual /update
w32tm /resync
```

---

## 🛡️ 네트워크/보안 고려

* **UDP/123(NTP)**: 많은 기업망에서 차단 (증폭 공격 방지).
  → 이 경우 **HTTP 폴백** 또는 **방화벽 예외** 필요
* **IPv6 경로 이슈**: 기본 구현은 **IPv4 강제**
* **프록시/SSL 검사**: HTTP 폴백에 영향 가능 (HEAD 요청 허용 여부)
* **로그/감사**: 시스템 시간 변경은 감사 대상일 수 있음

---

## 📈 정확도에 관하여

* 현재 구현은 **NTP Transmit Timestamp**를 사용하는 **단순(SNTP 스타일)** 응답 처리입니다.
  왕복 지연 보정(4타임스탬프 기반 오프셋 계산)을 넣으면 정확도를 더 높일 수 있습니다.
* HTTP Date 폴백은 초 단위 정확도에 가깝고, 중간 프록시/캐시 영향 가능성이 있습니다.

---

## 🩺 TroubleShooting

| 증상/오류                             	| 원인                               	| 해결                                                                    	|
| ------------------------------- 		| ----------------------------------    | -------------------------------------------------------------------------	|  
| 연결 실패, 타임아웃                	| 방화벽이 **UDP/123** 차단              | HTTP 폴백 활성화 또는 방화벽 예외 추가                                     	|
| IPv6 주소로만 응답, 실패            	| 경로/포트 차단                         | 기본 구현은 **IPv4 강제** 사용                                            	|
| `Win32Error=1314` (SetSystemTime) 	| **권한 없음(SeSystemtimePrivilege)**  | 관리자 승격 실행, 계정에 권한 부여, GPO 재정의 여부 확인 (`whoami /priv`)    	|
| `SocketException` 무작위 발생      	| 일시적 패킷 드롭/서버 이슈              | 재시도 횟수/타임아웃 증가, 서버 리스트 보강                                 	|
| HTTP 폴백도 실패                   	| 프록시/SSL 검사/HEAD 차단            	| GET로 재시도(코드 포함), 다른 URL 후보 추가                                 	|

---

## 🔐 권장 운영 패턴 요약

* **시스템 시각은 OS/정책(w32time/chrony)으로 관리**
* 애플리케이션은 **외부 UTC를 조회해 오프셋만 계산** (로그 타임스탬프, 만료 검증 등)
* 시스템 시간 변경은 **운영팀 승인 절차** + **감사 로그** 전제

---
## 🙋 FAQ

* **Q. Linux에서 시스템 시간을 코드로 바꿀 수 있나요?**
  A. 루트 권한이 필요하며 일반적으로 `timedatectl`/`chrony` 사용을 권장합니다. 앱에서 직접 변경은 지양하세요.

* **Q. 정확도를 더 높이고 싶습니다.**
  A. NTP 왕복 지연(4-타임스탬프) 오프셋 계산을 추가하세요. 필요 시 샘플 코드 제공 가능합니다.

* **Q. 서버 리스트를 바꿔도 되나요?**
  A. 가능합니다. 사내 NTP 어플라이언스가 있다면 최우선으로 넣으세요.

---
