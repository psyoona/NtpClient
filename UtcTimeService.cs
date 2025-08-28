using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace NtpClient
{
	internal class UtcTimeService
	{
		private string[] NtpServers { get; set; } =
		{
			"time.windows.com",
			"time.google.com",
			"time.cloudflare.com",
			"pool.ntp.org"
		};

		/// <summary>
		/// 외부 시계 기준 UTC. NTP 우선, 실패 시 HTTPS Date 헤더로 폴백.
		/// </summary>
		public async Task<DateTimeOffset> GetUtcNowAsync(int ntpTimeoutMs = 3000, int ntpRetries = 2, CancellationToken ct = default)
		{
			DateTimeOffset? ntpUtc = null;

			// 1) NTP 시도 (여러 서버, 재시도)
			foreach (var server in this.NtpServers)
			{
				for (int attempt = 0; attempt < ntpRetries; attempt++)
				{
					try
					{
						ntpUtc = await QueryNtpAsync(server, ntpTimeoutMs, ct).ConfigureAwait(false);

						break;
					}
					catch (SocketException) { /* 다음 시도 */ }
					catch (TimeoutException) { /* 다음 시도 */ }
					catch (Exception)
					{
						// 알 수 없는 오류는 다음 서버로 넘어감
						break;
					}
				}
				if (ntpUtc.HasValue)
					break;
			}

			// 2) 폴백: HTTPS Date 헤더 (대부분의 환경에서 443은 허용)
			if (!ntpUtc.HasValue)
			{
				//ntpUtc = await QueryHttpDateFallbackAsync(ct).ConfigureAwait(false);
			}

			return ntpUtc.Value;
		}

		/// <summary>
		/// 단일 NTP 서버 질의 (IPv4 강제, UDP/123). 성공 시 UTC 반환.
		/// </summary>
		private async Task<DateTimeOffset> QueryNtpAsync(string hostname, int timeoutMs, CancellationToken ct)
		{
			// 48바이트 NTP 메시지
			byte[] buffer = new byte[48];
			buffer[0] = 0x1B; // LI=0, VN=3, Mode=3 (client)

			// IPv4만 선택 (기업망에서 IPv6 경로가 막힌 경우가 많음)
			var ipv4 = (await Dns.GetHostAddressesAsync(hostname)).First(addr => addr.AddressFamily == AddressFamily.InterNetwork);
			var remote = new IPEndPoint(ipv4, 123);

			using var udp = new UdpClient(AddressFamily.InterNetwork);
			udp.Client.ReceiveTimeout = timeoutMs;
			udp.Client.SendTimeout = timeoutMs;

			// 일부 환경에서 바인드가 유리
			udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));

			// 송신
			await udp.SendAsync(buffer, buffer.Length, remote).ConfigureAwait(false);

			// 수신 (타임아웃 적용)
			var receiveTask = udp.ReceiveAsync();
			using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
			cts.CancelAfter(timeoutMs);

			UdpReceiveResult result;
			try
			{
				using (cts.Token.Register(() => udp.Close())) // 타임아웃 시 소켓 닫아 receive 해제
				{
					result = await receiveTask.ConfigureAwait(false);
				}
			}
			catch (ObjectDisposedException)
			{
				throw new TimeoutException("NTP 응답 시간 초과");
			}

			if (result.Buffer is null || result.Buffer.Length < 48)
				throw new SocketException((int)SocketError.MessageSize);

			// 40~47 바이트: Transmit Timestamp (서버가 보낸 시간)
			const int transmitTimeOffset = 40;
			uint intPart = ReadBigEndianUInt32(result.Buffer, transmitTimeOffset);
			uint fracPart = ReadBigEndianUInt32(result.Buffer, transmitTimeOffset + 4);

			// NTP epoch(1900-01-01) 기준 초/소수
			const ulong ntpEpochToUnixEpochSeconds = 2208988800UL; // 1970-1900
			ulong seconds = intPart;
			ulong fraction = fracPart;

			// 초 + 소수부(2^-32) → 밀리초
			double millis = (seconds * 1000d) + (fraction * 1000d / 4294967296d);

			// NTP epoch → Unix epoch 보정
			var unixMillis = millis - (ntpEpochToUnixEpochSeconds * 1000d);

			// UTC DateTimeOffset
			return DateTimeOffset.FromUnixTimeMilliseconds((long)unixMillis);
		}

		private uint ReadBigEndianUInt32(byte[] bytes, int offset)
		{
			// Big-endian → Little-endian
			return (uint)(
				(bytes[offset + 0] << 24) |
				(bytes[offset + 1] << 16) |
				(bytes[offset + 2] << 8) |
				(bytes[offset + 3] << 0));
		}

		/// <summary>
		/// 방화벽으로 UDP/123이 막힌 환경을 위한 폴백: HTTPS Date 헤더
		/// 정확도는 NTP보다 떨어지지만(초 단위) 외부 기준 시간을 확보 가능.
		/// </summary>
		private async Task<DateTimeOffset> QueryHttpDateFallbackAsync(CancellationToken ct)
		{
			// 다중 후보 (서버 중 하나만 성공해도 OK)
			string[] urls =
			{
				"https://www.google.com/generate_204",
				"https://www.cloudflare.com/cdn-cgi/trace",
				"https://www.microsoft.com"
			};

			using var http = new HttpClient(new SocketsHttpHandler
			{
				AllowAutoRedirect = false
			});

			foreach (var url in urls)
			{
				try
				{
					using var resp = await http.SendAsync(
						new HttpRequestMessage(HttpMethod.Head, url),
						HttpCompletionOption.ResponseHeadersRead,
						ct).ConfigureAwait(false);

					// Date 헤더가 없으면 GET 한번 더 시도
					var date = resp.Headers.Date ?? (await TryGetDateViaGetAsync(http, url, ct).ConfigureAwait(false));
					if (date.HasValue)
						return date.Value.ToUniversalTime();
				}
				catch { /* 다음 후보 시도 */ }
			}

			throw new InvalidOperationException("외부 기준 시간을 가져오지 못했습니다. (NTP/HTTP 모두 실패)");
		}

		/// <summary>
		/// 외부 시각을 조회해 시스템 시간을 동기화(Windows 전용). 
		/// driftThreshold: 드리프트가 이 초를 넘을 때만 반영 (기본 1초).
		/// </summary>
		public async Task<bool> SyncSystemClockAsync(double driftThresholdSeconds = 1.0, int ntpTimeoutMs = 3000, int ntpRetries = 2, CancellationToken ct = default)
		{
			// 1) 외부 UTC 획득
			var externalUtc = await GetUtcNowAsync(ntpTimeoutMs, ntpRetries, ct);

			// 2) 현재 로컬 시스템 UTC와 드리프트 계산
			var localUtc = DateTimeOffset.UtcNow;
			var drift = (externalUtc - localUtc).TotalSeconds;

			Console.WriteLine($"UTC Time from NTP Server: {externalUtc.ToString("yyyy-MM-dd HH:mm:ss")}");
			Console.WriteLine($"Local UTC Time: {localUtc.ToString("yyyy-MM-dd HH:mm:ss")}");

			// 임계치 이하면 변경 안 함 (로그만)
			if (Math.Abs(drift) < driftThresholdSeconds)
			{
				return false;
			}

			// 3) Windows 전용: 관리자 권한 필요
			if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
			{
				throw new PlatformNotSupportedException("Windows 전용 예시입니다. Linux는 timedatectl/chrony 등 사용 권장.");
			}

			EnsureSeSystemtimePrivilegeEnabled(); // 권한 활성

			// 4) SetSystemTime는 UTC 기준 SYSTEMTIME을 요구
			var utc = externalUtc.UtcDateTime;
			SYSTEMTIME st = new SYSTEMTIME
			{
				wYear = (ushort)utc.Year,
				wMonth = (ushort)utc.Month,
				wDay = (ushort)utc.Day,
				wHour = (ushort)utc.Hour,
				wMinute = (ushort)utc.Minute,
				wSecond = (ushort)utc.Second,
				wMilliseconds = (ushort)utc.Millisecond
			};

			if (!SetSystemTime(ref st))
			{
				var err = Marshal.GetLastWin32Error();
				throw new InvalidOperationException($"SetSystemTime 실패 (Win32Error={err})");
			}
			return true;
		}

		#region Win32: 권한/시간 설정 (Windows 전용)
		// SYSTEMTIME 구조체
		[StructLayout(LayoutKind.Sequential)]
		private struct SYSTEMTIME
		{
			public ushort wYear;
			public ushort wMonth;
			public ushort wDayOfWeek;
			public ushort wDay;
			public ushort wHour;
			public ushort wMinute;
			public ushort wSecond;
			public ushort wMilliseconds;
		}

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern bool SetSystemTime(ref SYSTEMTIME st);

		[DllImport("advapi32.dll", SetLastError = true)]
		private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

		[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

		[DllImport("advapi32.dll", SetLastError = true)]
		private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
			ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

		[DllImport("kernel32.dll")]
		private static extern IntPtr GetCurrentProcess();

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern bool CloseHandle(IntPtr hObject);

		private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
		private const uint TOKEN_QUERY = 0x0008;
		private const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";
		private const int SE_PRIVILEGE_ENABLED = 0x00000002;

		[StructLayout(LayoutKind.Sequential)]
		private struct LUID
		{
			public uint LowPart;
			public int HighPart;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct TOKEN_PRIVILEGES
		{
			public uint PrivilegeCount;
			public LUID Luid;
			public uint Attributes;
		}

		private static void EnsureSeSystemtimePrivilegeEnabled()
		{
			IntPtr hToken = IntPtr.Zero;
			try
			{
				if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
					throw new InvalidOperationException("OpenProcessToken 실패");

				if (!LookupPrivilegeValue(null, SE_SYSTEMTIME_NAME, out LUID luid))
					throw new InvalidOperationException("LookupPrivilegeValue 실패 (SeSystemtimePrivilege)");

				TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
				{
					PrivilegeCount = 1,
					Luid = luid,
					Attributes = SE_PRIVILEGE_ENABLED
				};

				if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
					throw new InvalidOperationException("AdjustTokenPrivileges 실패");
			}
			finally
			{
				if (hToken != IntPtr.Zero) CloseHandle(hToken);
			}
		}
		#endregion



		private static async Task<DateTimeOffset?> TryGetDateViaGetAsync(HttpClient http, string url, CancellationToken ct)
		{
			using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
			return resp.Headers.Date;
		}
	}
}
